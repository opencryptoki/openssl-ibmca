# How to contribute

Patches are more than welcome, even to fix a bug or to add a new feature.
Below are a few guidelines we ask of contributors to follow.

## Getting started

* Submit a [ticket](https://github.com/opencryptoki/openssl-ibmca/issues) for
 your issue, assuming one does not already exist.
  * Clearly describe the issue, including steps to reproduce when it is a bug.
  * Make sure you fill in the earliest version that you know has the issue.
  * Include information from your environment (OS, openssl-ibmca version,
 libica version, and any other related packages version).
* Fork the repository on GitHub.

## Making changes

These are not mandatory, but try to follow the steps bellow as good practices
 to contribute to (any open source) project:

* Create a topic/issue branch from the `master` branch.
```
$ git checkout master
Switched to branch 'master'
Your branch is up-to-date with 'origin/master'.
$ git checkout -t -b new_branch
Branch new_branch set up to track local branch master.
Switched to a new branch 'new_branch'
$
```
* Please avoid working directly on the `master` branch.
* If the changes are too big, please separate it into smaller, logical,
 commits. This will improve commit history and code review.
* Follow the [coding style](docs/coding_style.md) guidelines.
* Check for unnecessary whitespace with `git diff --check` before committing.
* Make sure your commit messages are in the proper format and sign your patch.
* Use GitHub [auto-closing](
    https://help.github.com/articles/closing-issues-via-commit-messages/)
 keywords in the commit message, make the commit message body as descriptive
 as necessary limited to 80 columns, and signoff your patch. Ex:
```
    Add CONTRIBUTING guidelines

    The CONTRIBUTING.md file describes the guidelines that every Contributor
    must follow to get their code integrated into OpenSSL-ibmca. This will
    improve Contributors/Maintainers work.

    Fixes #6

    Signed-off-by: YOUR_NAME <youremail@something.com>
```


## Submitting Changes

* [Signoff](https://git-scm.com/docs/git-commit#git-commit---signoff) your
 commits, as mentioned above.
* There are two ways to submit patches:
  * If you prefer the old school way of sending patches to a mailing-list, then
 feel free to send your patch to the [technical discussion mailing-list](
 https://sourceforge.net/projects/opencryptoki/lists/opencryptoki-tech). We
 will keep you posted as the code review goes by.
  * If you like GitHub and all the tools it has (like the Maintainers do), then
 submit a [Pull Request](
 https://help.github.com/articles/creating-a-pull-request/).
* Wait for your patch review and the Maintainers feedback about your changes.
