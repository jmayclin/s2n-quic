
#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let octocrab = octocrab::instance();

    let page = octocrab.repos("aws", "s2n-quic")
        .releases()
        .get_latest()
        .await.unwrap();
    println!("{:?}", page);
    let version = page.tag_name;
    let commit = page.target_commitish;
    println!("the version (tag) is {:?} and the commit is {:?}", version, commit);
    // get the previous release commit from github and release version

    // check that that is the version that we are currently on, otherwise there
    // a failed release in-between

    // get the list of commits that have happened since then.

    // calculate the proper version bumps

    // resolve the build problems

    // create a pr with the changes

    // ensure that no new commits have happened since then
}
