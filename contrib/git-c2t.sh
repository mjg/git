#!/bin/sh

die () {
	echo "$@"
	rm -f "$tagfile"
 	exit 1
}

warn () {
	echo "$@"
}

test $# -eq 2 || die "Usage: $0 <commit> <tagname>"

tagname="$2"
commit="$1"

git rev-parse --verify -q "$commit" >/dev/null || die "Cannot parse $commit."

test x$(git cat-file -t $commit) == "xcommit" || die "$commit is no commit."

tagfile=$(mktemp)

git cat-file commit "$commit" | {
	read drop tree
	test $drop == "tree" || die "No tree."
	read drop parent
	test $drop = "parent" || die "No parent."
	read drop author
	test $drop == "author" || die "No author."
	read drop committer
	test $drop == "committer" || die "No committer."
	test "$author" == "$committer" || warn "author $author != committer $committer, taking author."
	ptree=$(git cat-file -p $parent|fgrep tree|head -1|cut -d' ' -f2)
	test $ptree == $tree || die "commit $commit introduces a diff."
	cat <<EOF >$tagfile
object $parent
type commit
tag $tagname
tagger $author
EOF
	cat >>$tagfile
	hash=$(git hash-object -t tag -w "$tagfile")
	git tag "$tagname" $hash
}
rm -f $tagfile
