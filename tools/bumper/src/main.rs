use std::{process::Command, collections::HashMap};

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

    println!("successfully parsd the dependency graph: {:?}", dep_graph);

    let (version, commit) = get_release().await;

    println!("version: {:?}, commit: {:?}", version, commit);

    // get the previous release commit from github and release version

    // check that that is the version that we are currently on, otherwise there
    // a failed release in-between

    // get the list of commits that have happened since then.

    // calculate the proper version bumps

    // resolve the build problems

    // create a pr with the changes

    // ensure that no new commits have happened since then
}

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

    let dep_tree = Command::new("cargo").arg("tree")
        .arg("-p").arg(name)
        .arg("-e").arg("normal")
        .arg("--prefix").arg("depth").output().unwrap();

    // parse std out into a string
    let output = String::from_utf8(dep_tree.stdout).unwrap();

    // I could probably parse this more easily with a regex, but for now this is
    // fine
    output.lines().map(|l| {
        let depth_end = l.find(|c: char| c.is_alphabetic()).unwrap();
        let depth = l[0..depth_end].parse::<u8>().unwrap();
        let crate_name_end = l.find(' ').unwrap();
        let crate_name = &l[depth_end..crate_name_end];
        (depth, crate_name)
    })
    // only look at immediate dependencies
    .filter(|(depth, _name)| *depth == 1)
    // we only care about the crates we publish
    .filter(|(_depth, name)| interest_list.contains(name))
    .map(|(_depth, name)| name.to_owned())
    .collect()
}

async fn get_release() -> (String, String) {
    return ("v1.17.1".to_owned(), "a6c8fbe52596564d632343e7cb4969954a1098ff".to_owned());
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