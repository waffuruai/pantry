"""What we know how to check: each tool's binaries, how to read its version,
and how OSV (and endoflife.date) know it. Data only; tools.py finds them.

An OSV mapping is an ecosystem package, ("npm", "@openai/codex", "{v}"), or
an upstream repo plus its release-tag format, ("GIT", github("redis/redis"),
"{v}"). Tag formats: {v} the version, {v3} padded to three parts (8.10 →
8.10.0), {u} with dots as underscores, {ssh}
OpenSSH's V_9_6_P1 style. Check a new tag format exists with
`git ls-remote --tags <repo>`."""

from __future__ import annotations

from dataclasses import dataclass

from .system import github


@dataclass
class Tool:
    name: str
    kind: str
    bins: tuple
    args: tuple
    pattern: str
    osv: tuple = ()       # (ecosystem, package, tag format)
    eol: tuple = ()       # (endoflife.date product, cycle format)
    always: bool = False  # check it even when Homebrew or an app installed it (no one else does)
    paths: tuple = ()     # where version managers keep other installs, besides PATH


def major(v): return v.split(".")[0]
def minor(v): return ".".join(v.split(".")[:2])
def java(v): return v.split(".")[1] if v.startswith("1.") else v.split(".")[0]


# Where version managers keep every installed runtime, active or not.
NODE_DIRS = ("~/.nvm/versions/node/*/bin", "~/.volta/tools/image/node/*/bin",
             "~/.local/share/fnm/node-versions/*/installation/bin",
             "~/Library/Application Support/fnm/node-versions/*/installation/bin",
             "~/.asdf/installs/nodejs/*/bin", "~/.local/share/mise/installs/node/*/bin")
CONDA_DIRS = ("~/miniconda3", "~/anaconda3", "~/miniforge3", "~/mambaforge", "/opt/miniconda3",
              "/opt/homebrew/Caskroom/miniforge/base", "/opt/homebrew/Caskroom/miniconda/base")
PYTHON_DIRS = ("~/.pyenv/versions/*/bin", "~/.local/share/uv/python/*/bin", "~/.asdf/installs/python/*/bin",
               "~/.local/share/mise/installs/python/*/bin",
               *(f"{d}/bin" for d in CONDA_DIRS), *(f"{d}/envs/*/bin" for d in CONDA_DIRS))
RUBY_DIRS = ("~/.rbenv/versions/*/bin", "~/.rvm/rubies/*/bin", "~/.asdf/installs/ruby/*/bin",
             "~/.local/share/mise/installs/ruby/*/bin")
GO_DIRS = ("/usr/local/go/bin", "~/sdk/go*/bin", "~/.asdf/installs/golang/*/go/bin",
           "~/.local/share/mise/installs/go/*/bin")
JAVA_DIRS = ("~/.sdkman/candidates/java/*/bin", "/Library/Java/JavaVirtualMachines/*/Contents/Home/bin")

TOOLS = (
    # Runtimes and compilers
    Tool("node", "runtime", ("node",), ("--version",), r"v(\d+\.\d+\.\d+)",
         ("GIT", github("nodejs/node"), "v{v}"), ("nodejs", major), paths=NODE_DIRS),
    Tool("go", "runtime", ("go",), ("env", "GOVERSION"), r"go(\d+\.\d+(?:\.\d+)?)",
         ("Go", "stdlib", "{v}"), ("go", minor), paths=GO_DIRS),
    Tool("rust", "runtime", ("rustc",), ("--version",), r"rustc (\d+\.\d+\.\d+)",
         ("GIT", github("rust-lang/rust"), "{v}"), paths=("~/.rustup/toolchains/*/bin",)),
    Tool("ruby", "runtime", ("ruby",), ("--version",), r"ruby (\d+\.\d+\.\d+)",
         ("GIT", github("ruby/ruby"), "v{u}"), ("ruby", minor), paths=RUBY_DIRS),
    Tool("php", "runtime", ("php",), ("-v",), r"PHP (\d+\.\d+\.\d+)",
         ("GIT", github("php/php-src"), "php-{v}"), ("php", minor)),
    Tool("java", "runtime", ("java",), ("-version",), r'version "(\d+(?:\.\d+)*)',
         (), ("eclipse-temurin", java), paths=JAVA_DIRS),
    Tool("deno", "runtime", ("deno",), ("--version",), r"deno (\d+\.\d+\.\d+)",
         ("GIT", github("denoland/deno"), "v{v}"), paths=("~/.deno/bin",)),
    Tool("bun", "runtime", ("bun",), ("--version",), r"^(\d+\.\d+\.\d+)",
         ("GIT", github("oven-sh/bun"), "bun-v{v}"), paths=("~/.bun/bin",)),
    Tool("swift", "compiler", ("swift",), ("--version",), r"^Swift version (\d+\.\d+(?:\.\d+)?)",
         ("GIT", github("swiftlang/swift"), "swift-{v}-RELEASE")),
    Tool("clang", "compiler", ("clang", "clang++"), ("--version",), r"^clang version (\d+\.\d+\.\d+)",
         ("GIT", github("llvm/llvm-project"), "llvmorg-{v}")),
    Tool("gcc", "compiler", ("gcc", "g++"), ("--version",), r"^g(?:cc|\+\+)\S* \(.*\) (\d+\.\d+\.\d+)",
         ("GIT", github("gcc-mirror/gcc"), "releases/gcc-{v}")),
    # Version managers (python itself is found by packages.pythons)
    Tool("fnm", "manager", ("fnm",), ("--version",), r"fnm (\d+\.\d+\.\d+)", ("GIT", github("Schniz/fnm"), "v{v}")),
    Tool("volta", "manager", ("volta",), ("--version",), r"^(\d+\.\d+\.\d+)",
         ("GIT", github("volta-cli/volta"), "v{v}"), paths=("~/.volta/bin",)),
    Tool("rbenv", "manager", ("rbenv",), ("--version",), r"rbenv (\d+\.\d+\.\d+)",
         ("GIT", github("rbenv/rbenv"), "v{v}")),
    Tool("pyenv", "manager", ("pyenv",), ("--version",), r"pyenv (\d+\.\d+\.\d+)",
         ("GIT", github("pyenv/pyenv"), "v{v}"), paths=("~/.pyenv/bin",)),
    Tool("asdf", "manager", ("asdf",), ("--version",), r"v?(\d+\.\d+\.\d+)", ("GIT", github("asdf-vm/asdf"), "v{v}")),
    Tool("mise", "manager", ("mise",), ("--version",), r"^(\d+\.\d+\.\d+)", ("GIT", github("jdx/mise"), "v{v}")),
    Tool("rustup", "manager", ("rustup",), ("--version",), r"rustup (\d+\.\d+\.\d+)",
         ("GIT", github("rust-lang/rustup"), "{v}"), paths=("~/.cargo/bin",)),
    Tool("conda", "manager", ("conda",), ("--version",), r"conda (\d+\.\d+\.\d+)",
         ("GIT", github("conda/conda"), "{v}"), paths=tuple(f"{d}/bin" for d in CONDA_DIRS)),
    # Package managers (pip and npm are found per runtime, in packages.py)
    Tool("uv", "pkgmgr", ("uv",), ("--version",), r"uv (\d+\.\d+\.\d+)", ("PyPI", "uv", "{v}")),
    Tool("pipx", "pkgmgr", ("pipx",), ("--version",), r"^(\d+\.\d+\.\d+)", ("PyPI", "pipx", "{v}")),
    Tool("poetry", "pkgmgr", ("poetry",), ("--version",), r"(\d+\.\d+\.\d+)", ("PyPI", "poetry", "{v}")),
    Tool("pnpm", "pkgmgr", ("pnpm",), ("--version",), r"^(\d+\.\d+\.\d+)", ("npm", "pnpm", "{v}")),
    Tool("yarn", "pkgmgr", ("yarn",), ("--version",), r"^(1\.\d+\.\d+)", ("npm", "yarn", "{v}")),
    Tool("gem", "pkgmgr", ("gem",), ("--version",), r"^(\d+\.\d+\.\d+)", ("GIT", github("rubygems/rubygems"), "v{v}")),
    Tool("bundler", "pkgmgr", ("bundle",), ("--version",), r"(\d+\.\d+\.\d+)", ("RubyGems", "bundler", "{v}")),
    Tool("composer", "pkgmgr", ("composer",), ("--version",), r"Composer version (\d+\.\d+\.\d+)",
         ("Packagist", "composer/composer", "{v}")),
    Tool("brew", "pkgmgr", ("brew",), ("--version",), r"Homebrew (\d+\.\d+\.\d+)",
         ("GIT", github("Homebrew/brew"), "{v}")),
    # Build and developer tools
    Tool("git", "tool", ("git",), ("--version",), r"git version (\d+\.\d+\.\d+)", ("GIT", github("git/git"), "v{v}")),
    Tool("gh", "tool", ("gh",), ("--version",), r"gh version (\d+\.\d+\.\d+)", ("Go", "github.com/cli/cli/v2", "{v}")),
    Tool("git-lfs", "tool", ("git-lfs",), ("--version",), r"git-lfs/(\d+\.\d+\.\d+)",
         ("Go", "github.com/git-lfs/git-lfs/v3", "{v}")),
    Tool("openssl", "tool", ("openssl",), ("version",), r"^OpenSSL (\d+\.\d+\.\d+)",
         ("GIT", github("openssl/openssl"), "openssl-{v}"), ("openssl", minor)),
    Tool("curl", "tool", ("curl",), ("--version",), r"^curl (\d+\.\d+\.\d+)", ("GIT", github("curl/curl"), "curl-{u}")),
    Tool("ssh", "tool", ("ssh",), ("-V",), r"OpenSSH_(\d+\.\d+p\d+)",
         ("GIT", github("openssh/openssh-portable"), "V_{ssh}")),
    Tool("cmake", "tool", ("cmake",), ("--version",), r"cmake version (\d+\.\d+\.\d+)",
         ("GIT", github("Kitware/CMake"), "v{v}")),
    Tool("gradle", "tool", ("gradle",), ("--version",), r"Gradle (\d+\.\d+(?:\.\d+)?)",
         ("GIT", github("gradle/gradle"), "v{v3}")),
    Tool("maven", "tool", ("mvn",), ("--version",), r"Apache Maven (\d+\.\d+\.\d+)",
         ("GIT", github("apache/maven"), "maven-{v}")),
    Tool("bazel", "tool", ("bazel",), ("--version",), r"bazel (\d+\.\d+\.\d+)", ("GIT", github("bazelbuild/bazel"), "{v}")),
    Tool("kubectl", "tool", ("kubectl",), ("version", "--client", "-o", "json"),
         r'"gitVersion":\s*"v(\d+\.\d+\.\d+)"', ("Go", "k8s.io/kubernetes", "{v}")),
    Tool("terraform", "tool", ("terraform",), ("version",), r"Terraform v(\d+\.\d+\.\d+)",
         ("Go", "github.com/hashicorp/terraform", "{v}")),
    Tool("helm", "tool", ("helm",), ("version", "--short"), r"v(\d+\.\d+\.\d+)", ("Go", "helm.sh/helm/v3", "{v}")),
    Tool("aws", "tool", ("aws",), ("--version",), r"aws-cli/(\d+\.\d+\.\d+)", ("GIT", github("aws/aws-cli"), "{v}")),
    Tool("nginx", "tool", ("nginx",), ("-v",), r"nginx/(\d+\.\d+\.\d+)",
         ("GIT", github("nginx/nginx"), "release-{v}"), ("nginx", minor)),
    Tool("caddy", "tool", ("caddy",), ("version",), r"^v(\d+\.\d+\.\d+)", ("Go", "github.com/caddyserver/caddy/v2", "{v}")),
    # AI coding harnesses installed outside npm and pipx (those listings cover the rest)
    Tool("claude", "harness", ("claude",), ("--version",), r"^(\d+\.\d+\.\d+)",
         ("npm", "@anthropic-ai/claude-code", "{v}"), paths=("~/.claude/local", "~/.local/bin")),
    Tool("codex", "harness", ("codex",), ("--version",), r"codex-cli (\d+\.\d+\.\d+)", ("npm", "@openai/codex", "{v}")),
    Tool("opencode", "harness", ("opencode",), ("--version",), r"^(\d+\.\d+\.\d+)", ("npm", "opencode-ai", "{v}"),
         paths=("~/.opencode/bin",)),
    Tool("openclaw", "harness", ("openclaw",), ("--version",), r"(\d{4}\.\d+\.\d+)", ("npm", "openclaw", "{v}")),
    Tool("pi", "harness", ("pi",), ("--version",), r"^(\d+\.\d+\.\d+)$", ("npm", "@mariozechner/pi-coding-agent", "{v}")),
    Tool("gemini", "harness", ("gemini",), ("--version",), r"^(\d+\.\d+\.\d+)", ("npm", "@google/gemini-cli", "{v}")),
    Tool("qwen", "harness", ("qwen",), ("--version",), r"^(\d+\.\d+\.\d+)", ("npm", "@qwen-code/qwen-code", "{v}")),
    Tool("kilo", "harness", ("kilo",), ("--version",), r"(\d+\.\d+\.\d+)", ("npm", "@kilocode/cli", "{v}")),
    Tool("hermes", "harness", ("hermes",), ("--version",), r"(\d+\.\d+\.\d+)", ("PyPI", "hermes-agent", "{v}"),
         paths=("~/.hermes/bin", "~/.local/bin")),
    Tool("aider", "harness", ("aider",), ("--version",), r"aider (\d+\.\d+\.\d+)", ("PyPI", "aider-chat", "{v}")),
    Tool("goose", "harness", ("goose",), ("--version",), r"(\d+\.\d+\.\d+)", ("GIT", github("block/goose"), "v{v}")),
    Tool("crush", "harness", ("crush",), ("--version",), r"(\d+\.\d+\.\d+)",
         ("GIT", github("charmbracelet/crush"), "v{v}")),
    # Datastores and queues. PostgreSQL's advisories come from the project's own
    # table (feeds.postgres): OSV, and so `brew vulns`, has no PostgreSQL data.
    Tool("postgres", "datastore", ("postgres", "psql"), ("--version",), r"\(PostgreSQL\) (\d+\.\d+)",
         (), ("postgresql", major), always=True, paths=("/Applications/Postgres.app/Contents/Versions/*/bin",)),
    Tool("mongodb", "datastore", ("mongod",), ("--version",), r"db version v(\d+\.\d+\.\d+)",
         ("GIT", github("mongodb/mongo"), "r{v}"), ("mongodb", minor)),
    Tool("mongosh", "datastore", ("mongosh",), ("--version",), r"^(\d+\.\d+\.\d+)", ("npm", "mongosh", "{v}")),
    Tool("redis", "datastore", ("redis-server",), ("--version",), r"Redis server v=(\d+\.\d+\.\d+)",
         ("GIT", github("redis/redis"), "{v}"), ("redis", minor)),
    Tool("valkey", "datastore", ("valkey-server",), ("--version",), r"v=(\d+\.\d+\.\d+)",
         ("GIT", github("valkey-io/valkey"), "{v}"), ("valkey", minor)),
    Tool("mariadb", "datastore", ("mariadbd", "mariadb", "mysqld", "mysql"), ("--version",),
         r"(\d+\.\d+\.\d+)-MariaDB", ("GIT", github("MariaDB/server"), "mariadb-{v}"), ("mariadb", minor)),
    Tool("mysql", "datastore", ("mysqld", "mysql"), ("--version",), r"Ver (\d+\.\d+\.\d+)(?![\d.]*-MariaDB)",
         ("GIT", github("mysql/mysql-server"), "mysql-{v}"), ("mysql", minor)),
    Tool("sqlite", "datastore", ("sqlite3",), ("--version",), r"^(\d+\.\d+\.\d+)",
         ("GIT", github("sqlite/sqlite"), "version-{v}")),
    Tool("duckdb", "datastore", ("duckdb",), ("--version",), r"v(\d+\.\d+\.\d+)", ("GIT", github("duckdb/duckdb"), "v{v}")),
    Tool("memcached", "datastore", ("memcached",), ("-V",), r"memcached (\d+\.\d+\.\d+)",
         ("GIT", github("memcached/memcached"), "{v}")),
    Tool("etcd", "datastore", ("etcd",), ("--version",), r"etcd Version: (\d+\.\d+\.\d+)",
         ("Go", "go.etcd.io/etcd/server/v3", "{v}")),
    Tool("kafka", "queue", ("kafka-topics", "kafka-topics.sh"), ("--version",), r"^(\d+\.\d+\.\d+)",
         ("GIT", github("apache/kafka"), "{v}")),
    Tool("nats", "queue", ("nats-server",), ("--version",), r"v(\d+\.\d+\.\d+)",
         ("Go", "github.com/nats-io/nats-server/v2", "{v}")),
)
