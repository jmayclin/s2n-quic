use std::{
    collections::{HashMap, HashSet},
    error::Error,
    process::Command,
    str::FromStr, fmt::Display,
};

use cargo_toml::{Manifest, Inheritable, Dependency};

#[derive(Copy, Clone, Debug)]
enum Bump {
    PATCH,
    MINOR,
    // we explicitly do not handle breaking changes
    // they are rare enough and high risk enough that
    // a human should explicitly be in the loop on them
    //MAJOR
}

#[derive(Debug, Clone)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl FromStr for Version {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tokens = s.split('.');
        let major = tokens.next().unwrap().parse()?;
        let minor = tokens.next().unwrap().parse()?;
        let patch = tokens.next().unwrap().parse()?;
        Ok(Version {
            major,
            minor,
            patch,
        })
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Version {
    fn bump(&mut self, bump: Bump) {
        match bump {
            PATCH => {self.patch += 1},
            MINOR => {self.minor += 1},
        };
    }
}

#[tokio::main]
async fn main() {
    // these are the crates that we actually care to publish
    let crates = vec![
        "quic/s2n-quic-core",
        "quic/s2n-quic-platform",
        "quic/s2n-quic-crypto",
        "quic/s2n-quic-rustls",
        "quic/s2n-quic-tls",
        "quic/s2n-quic-tls-default",
        "quic/s2n-quic-transport",
        "quic/s2n-quic",
        "common/s2n-codec",
    ];

    let crate_names: Vec<&str> = crates
        .iter()
        .map(|path| path.split_once("/").unwrap().1)
        .collect();

    // build dependency graph
    // we want a list of the immediate dependencies for each of our crates of
    // interest. This is used to calculate which crates need to have their
    // versions bumped.
    // package -> [consumers], e.g. s2n-quic-transport -> [s2n-quic]
    let mut dep_graph: HashMap<String, Vec<String>> = HashMap::new();

    // we can not just look at the dependency graph for, e.g. s2n-quic, because
    // some crates, like s2n-quic-rustls won't show up in it. So we look at each
    for name in crate_names.iter().cloned() {
        let deps = get_dependencies(name, &crate_names);
        for d in deps {
            dep_graph.entry(d).or_default().push(name.to_owned());
        }
    }
    println!("dependency graph: {:?}", dep_graph);

    let (version, previous_release_commit) = get_release().await;
    println!(
        "version: {:?}, commit: {:?}",
        version, previous_release_commit
    );

    let commits = get_commits(&previous_release_commit);
    println!("commits: {:?}", commits);

    let changed_files = get_changed_files(&previous_release_commit);
    let changed_crates: Vec<String> = crates
        .iter()
        .filter(|release_crate| {
            changed_files
                .iter()
                .any(|file| file.starts_with(**release_crate))
        })
        .map(|release_crate| (*release_crate).to_owned())
        .collect();
    let mut bumps = HashMap::new();

    for release_crate in changed_crates {
        bumps.insert(release_crate, Bump::PATCH);
    }
    println!("bumps: {:?}", bumps);

    let feat_files: HashSet<String> = commits
        .iter()
        .filter(|(_hash, description)| description.starts_with("feat"))
        .map(|(hash, _desciption)| get_changed_files(hash))
        .flatten()
        .collect();
    let changed_crates: Vec<String> = crates
        .iter()
        .filter(|release_crate| {
            changed_files
                .iter()
                .any(|file| file.starts_with(**release_crate))
        })
        .map(|release_crate| (*release_crate).to_owned())
        .collect();

    for release_crate in changed_crates {
        bumps.insert(release_crate, Bump::MINOR);
    }

    println!("bumps: {:?}", bumps);

    // for any package that has been changed, it's consumers must at least do a
    // minor bump to actually consume the updated dependency
    loop {
        // we have a "cascading" update as we go through the dependency chain,
        // so keep looping until we have reached a steady state.
        let mut change = false;
        // iterate over the crates instead of bumps to avoid the mut borrow issues
        for release_crate in crates.iter() {
            // if a crate is going to have a version bump, then all of the
            // consumers must have at least a patch bump
            if bumps.contains_key(*release_crate) {
                let consumers = match dep_graph.get(*release_crate) {
                    Some(c) => c,
                    None => continue,
                };
                // might not have any consumers, in which case skip
                for consumer in consumers {
                    if !bumps.contains_key(consumer) {
                        change = true;
                        bumps.insert(consumer.clone(), Bump::PATCH);
                    }
                }
            }
        }

        if !change {
            break;
        }
    }

    let toml = cargo_toml::Manifest::from_path("./quic/s2n-quic-core/Cargo.toml").unwrap();
    println!("{:?}", toml);
    let md = toml.package();
    println!("package metadata");
    println!("{:?}", md);
    let version = md.version();
    println!("crate version is {:?}", version);
    println!("crate build deps: {:?}", toml.dependencies);

    let mut versions = HashMap::new();
    let mut manifests = HashMap::new();
    for c in crates.iter() {
        let manifest_path = format!("{c}/Cargo.toml");
        let manifest_string = std::fs::read_to_string(&manifest_path).unwrap();
        let manifest = Manifest::from_path(&manifest_path).unwrap();
        let version: Version = manifest.package().version().parse().unwrap();
        manifests.insert(*c, manifest_string);
        versions.insert((*c).to_owned(), version);
    }

    println!("parsed versions: {:?}", versions);

    // update the version for each crate
    //for (c, manifest) in manifests.iter_mut() {
    //    let new_version = versions.get(c).unwrap();
    //    let package = manifest.package.as_mut().unwrap();
    //    package.version = Inheritable::Set(new_version.to_string());
    //
    //    // update the dependencies
    //    let deps = &mut manifest.dependencies;
    //    for (crate_path, _bump) in versions.iter() {
    //        let crate_name = crate_name_from_path(crate_path);
    //            if let Some(dep) = deps.get_mut(crate_name) {
    //                if let Dependency::Detailed(detail) = dep {
    //                    let dep_version = versions.get(crate_path).unwrap();
    //                    detail.version = Some(format!("={}", dep_version));
    //                } else {
    //                    panic!("I was not prepared for this");
    //                }
    //            }
    //    }
    //}

    // rewrite the Cargo.toml files
    let manifest = manifests.get("quic/s2n-quic-core").unwrap();
    let manifest_str = toml::to_string(manifest).unwrap();
    println!("manifest string is {}", manifest_str);


    // just figure out what has had the feature release.
    // if it hasn't had a feature release, figure out what gets a patch by simply looking
    // at the diffs between the last release and the current point in time.

    // get the previous release commit from github and release version

    // check that that is the version that we are currently on, otherwise there
    // a failed release in-between

    // get the list of commits that have happened since then.

    // calculate the proper version bumps

    // resolve the build problems

    // create a pr with the changes

    // ensure that no new commits have happened since then
}

/// `get_dependencies` shells out to `cargo tree` to calculate the direct
/// dependencies for the crate `name`. All crates except for those in
/// `interest_list` are dropped from the dependency tree.
fn get_dependencies(name: &str, interest_list: &Vec<&str>) -> Vec<String> {
    // example output of the dep tree
    // 0s2n-quic v1.17.1 (/home/ubuntu/workspace/s2n-quic/quic/s2n-quic)
    // 1bytes v1.4.0
    // 1cfg-if v1.0.0
    // 1cuckoofilter v0.5.0
    // 2byteorder v1.4.3
    // 2fnv v1.0.7
    // 2rand v0.7.3
    // 3getrandom v0.1.16
    // 4cfg-if v1.0.0
    // 4libc v0.2.140
    // 3libc v0.2.140
    // 3rand_chacha v0.2.2
    // 4ppv-lite86 v0.2.17

    let dep_tree = Command::new("cargo")
        .arg("tree")
        .arg("-p")
        .arg(name)
        .arg("-e")
        .arg("normal")
        .arg("--prefix")
        .arg("depth")
        .output()
        .unwrap();

    // parse std out into a string
    let output = String::from_utf8(dep_tree.stdout).unwrap();

    // I could probably parse this more easily with a regex, but for now this is
    // fine
    output
        .lines()
        .map(|l| {
            let depth_end = l.find(|c: char| c.is_alphabetic()).unwrap();
            let depth = l[0..depth_end].parse::<u8>().unwrap();
            let crate_name_end = l.find(' ').unwrap();
            let crate_name = &l[depth_end..crate_name_end];
            (depth, crate_name)
        })
        // only look at direct dependencies
        .filter(|(depth, _name)| *depth == 1)
        // we only care about the crates we publish
        .filter(|(_depth, name)| interest_list.contains(name))
        .map(|(_depth, name)| name.to_owned())
        .collect()
}

async fn get_release() -> (String, String) {
    //return ("v1.17.1".to_owned(), "a6c8fbe52596564d632343e7cb4969954a1098ff".to_owned());
    return (
        "v1.17.0".to_owned(),
        "db9671be670549421845e5b869b7a2e0735d2aca".to_owned(),
    );
    let octocrab = octocrab::instance();

    let page = octocrab
        .repos("aws", "s2n-quic")
        .releases()
        .get_latest()
        .await
        .unwrap();
    let version = page.tag_name;
    let commit = page.target_commitish;
    (version, commit)
}
/// get_commits returns all of the commits that have happend since
/// previous_release_commit
fn get_commits(previous_release_commit: &str) -> Vec<(String, String)> {
    // example output from the git log output
    // 41adde17 failing attempt with single dependency tree
    // 9d44dcde retrieve version and commit from github
    // 7497f1ab initial commit of bumper crate

    let git_commits = Command::new("git")
        .arg("log")
        .arg("--oneline")
        // don't add extraenous information like branch name
        .arg("--no-decorate")
        // use the full commit hash because we aren't barbarians
        .arg("--no-abbrev-commit")
        // include all commits from the previous_release_commit to HEAD
        .arg(format!("{previous_release_commit}..HEAD"))
        .output()
        .unwrap();
    String::from_utf8(git_commits.stdout)
        .unwrap()
        .lines()
        .map(|line| line.split_once(' ').unwrap())
        .map(|(hash, description)| (hash.to_owned(), description.to_owned()))
        .collect()
}

/// `get_changed_files_range` will return all the files that have been changed
/// after `previous_release_commit`.
fn get_changed_files_range(previous_release_commit: &str) -> Vec<String> {
    let file_diff = Command::new("git")
        .arg("diff")
        .arg(previous_release_commit)
        .arg("--name-only")
        .output()
        .unwrap();
    String::from_utf8(file_diff.stdout)
        .unwrap()
        .lines()
        .map(|line| line.to_owned())
        .collect()
}

/// `get_changed_files` will get the files that were changed in a specific
/// `commit` by shelling out to `git diff-tree`.
fn get_changed_files(commit: &str) -> Vec<String> {
    let file_diff = Command::new("git")
        .arg("diff-tree")
        .arg("--no-commit-id")
        .arg("--name-only")
        .arg(commit)
        .arg("-r")
        .output()
        .unwrap();
    String::from_utf8(file_diff.stdout)
        .unwrap()
        .lines()
        .map(|line| line.to_owned())
        .collect()
}

fn crate_name_from_path(path: &str) -> &str {
    path.split_once("/").unwrap().1
}