use super::*;
use crate::utils::temp::TempDir;

#[test]
fn a_view_stats_once_and_reads_its_head_once() {
    let d = TempDir::new("view").unwrap();
    let p = d.path().join("a.sh");
    std::fs::write(&p, "#!/bin/sh\necho hi\n").unwrap();
    let v = FileView::new(p.clone());
    assert!(v.stat().is_some_and(|s| s.file && !s.link && s.size == 18));
    assert_eq!(&v.head()[..2], b"#!");
    assert_eq!(v.head().len(), 18);
    assert_eq!(opens(&p), 1, "the head is read once");
    assert_eq!(v.read(1 << 20).map(|b| b.len()), Some(18));
    assert_eq!(opens(&p), 2);
}

#[test]
fn a_load_reads_the_head_then_the_whole_once() {
    let d = TempDir::new("view").unwrap();
    let sh = d.path().join("run.sh");
    std::fs::write(&sh, "#!/bin/sh\necho hi\n").unwrap();
    let txt = d.path().join("notes.txt");
    std::fs::write(&txt, "just words\n").unwrap();
    let program = |h: &[u8]| h.starts_with(b"#!");
    let (head, whole) = FileView::new(sh.clone()).load(0, 100, program);
    assert_eq!((&head[..2], whole.map(|b| b.len())), (&b"#!"[..], Some(18)));
    assert_eq!(opens(&sh), 1);
    let (head, whole) = FileView::new(txt.clone()).load(0, 100, program);
    assert_eq!((head.len(), whole), (11, None), "not a program: its head only");
    assert_eq!(FileView::new(txt.clone()).load(100, 0, program).1.map(|b| b.len()), Some(11), "read whole always");
    assert_eq!(FileView::new(txt.clone()).load(5, 0, program).1, None, "over the cap");
    assert_eq!(FileView::new(d.path().to_path_buf()).load(100, 100, program), (Vec::new(), None), "a directory");
    assert_eq!(FileView::new(d.path().join("gone")).load(100, 100, program), (Vec::new(), None));
    let big = d.path().join("big.sh");
    std::fs::write(&big, [b"#!".as_slice(), &[b'x'; 200]].concat()).unwrap();
    assert_eq!(FileView::new(big.clone()).load(0, 202, program).1.map(|b| b.len()), Some(202), "past the head");
}

#[test]
fn caps_links_and_missing_files() {
    let d = TempDir::new("view").unwrap();
    let big = d.path().join("big");
    std::fs::write(&big, vec![b'x'; 100]).unwrap();
    assert_eq!(FileView::new(big.clone()).read(10), None, "over the cap");
    assert_eq!(FileView::new(big.clone()).head().len(), HEAD, "the head of a file over the cap");
    let gone = FileView::new(d.path().join("gone"));
    assert_eq!((gone.stat(), gone.read(10), gone.head().len()), (None, None, 0));
    #[cfg(unix)]
    {
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&big, &link).unwrap();
        assert!(FileView::new(link).stat().is_some_and(|s| s.file && s.link));
        assert!(FileView::new(d.path().to_path_buf()).stat().is_some_and(|s| !s.file && !s.link));
    }
}
