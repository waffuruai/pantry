use super::*;

#[test]
fn frameworks_and_projects() {
    let text = r#"{"version": 2, "dependencies": {
            "net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"},
                       "local": {"type": "Project", "dependencies": {"Serilog": "[3.1.1, )"}},
                       "Serilog": {"type": "CentralTransitive", "requested": "[3.1.1, )", "resolved": "3.1.1"}},
            "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}}}}"#;
    let got: Vec<String> = parse(text).unwrap().iter().map(|p| format!("{} {}", p.name, p.version)).collect();
    assert_eq!(got, ["Newtonsoft.Json 13.0.3", "Newtonsoft.Json 13.0.1", "Serilog 3.1.1"]);
}
