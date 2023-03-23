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

    //let dep_graph = petgraph::Graph::new();
    //
    //crate_names.iter().map(|name| String::from(name)).for_each(|name| dep_graph.a)

    // build dependency graph
    // we want a list of the immediate dependencies for each of our crates of
    // interest. This is used to calculate which crates need to have their
    // versions bumped.

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
        .arg("-p").arg("s2n-quic")
        .arg("-e").arg("normal")
        .arg("--prefix").arg("depth").output().unwrap();

    // parse std out into a string
    let output = String::from_utf8(dep_tree.stdout).unwrap();

    // I could probably parse this more easily with a regex, but for now this is
    // fine
    let mut deps: Vec<(u8, &str)> = output.lines().map(|l| {
        let depth_end = l.find(|c: char| c.is_alphabetic()).unwrap();
        let depth = l[0..depth_end].parse::<u8>().unwrap();
        let crate_name_end = l.find(' ').unwrap();
        let crate_name = &l[depth_end..crate_name_end];
        (depth, crate_name)
    })
    .filter(|(_depth, name)| crate_names.contains(name))
    .collect();

    // we can not just look at the dependency graph for, e.g. s2n-quic, because
    // some crates, like s2n-quic-rustls won't show up in it. So we look at each
    // crate

    let mut dep_graph: HashMap<String, Vec<String>> = HashMap::new();

    println!("deps: {:?}", deps);
    let mut dep_stack = Vec::new();
    let mut deps = deps.drain(..);
    dep_stack.push(deps.next().unwrap());
    for (depth, name) in deps {
        while depth <= dep_stack.last().unwrap().0 {
            // remove the non-relevant entries
            // pop off all elements that are the same depth or deeper
            // than the new element
            dep_stack.pop();
        }
        let consumers = dep_graph.entry(name.to_owned()).or_default();
        consumers.push(dep_stack.last().unwrap().1.to_owned());

        dep_stack.push((depth, name));
    }


    //println!("deps: {:?}", deps);

    //println!("parsed output is {}", output);

    println!("graph: {:?}", dep_graph);

    return;



    println!("Hello, world!");
    let octocrab = octocrab::instance();

    let page = octocrab
        .repos("aws", "s2n-quic")
        .releases()
        .get_latest()
        .await
        .unwrap();
    println!("{:?}", page);
    let version = page.tag_name;
    let commit = page.target_commitish;
    println!(
        "the version (tag) is {:?} and the commit is {:?}",
        version, commit
    );
    // get the previous release commit from github and release version

    // check that that is the version that we are currently on, otherwise there
    // a failed release in-between

    // get the list of commits that have happened since then.

    // calculate the proper version bumps

    // resolve the build problems

    // create a pr with the changes

    // ensure that no new commits have happened since then
}
