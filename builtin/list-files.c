#include "cache.h"
#include "builtin.h"
#include "parse-options.h"
#include "pathspec.h"
#include "dir.h"
#include "quote.h"
#include "column.h"

static struct pathspec pathspec;
static const char *prefix;
static int prefix_length;
static unsigned int colopts;
static int max_depth;

static const char * const ls_usage[] = {
	N_("git list-files [options] [<pathspec>...]"),
	NULL
};

struct option ls_options[] = {
	OPT_COLUMN('C', "column", &colopts, N_("show files in columns")),
	OPT_SET_INT('1', NULL, &colopts,
		    N_("shortcut for --no-column"), COL_PARSEOPT),
	{ OPTION_INTEGER, 0, "max-depth", &max_depth, N_("depth"),
	  N_("descend at most <depth> levels"), PARSE_OPT_NONEG,
	  NULL, 1 },
	OPT_SET_INT('R', "recursive", &max_depth,
		    N_("shortcut for --max-depth=-1"), -1),
	OPT_END()
};

static void add_one(struct string_list *result, const char *name,
		    const char *tag)
{
	struct strbuf sb = STRBUF_INIT;
	struct string_list_item *item;

	quote_path_relative(name, prefix_length ? prefix : NULL, &sb);
	strbuf_insert(&sb, 0, "   ", 3);
	sb.buf[0] = tag[0];
	sb.buf[1] = tag[1];
	item = string_list_append(result, strbuf_detach(&sb, NULL));
	item->util = (char *)name;
}

static void populate_cached_entries(struct string_list *result,
				    const struct index_state *istate)
{
	int i;

	for (i = 0; i < istate->cache_nr; i++) {
		const struct cache_entry *ce = istate->cache[i];

		if (!match_pathspec(&pathspec, ce->name, ce_namelen(ce),
				    0, NULL,
				    S_ISDIR(ce->ce_mode) ||
				    S_ISGITLINK(ce->ce_mode)))
			continue;

		add_one(result, ce->name, "  ");
	}
}

static void cleanup_tags(struct string_list *result)
{
	int i, same_1 = 1, same_2 = 1, pos, len;

	for (i = 1; i < result->nr && (same_1 || same_2); i++) {
		const char *s0 = result->items[i - 1].string;
		const char *s1 = result->items[i].string;

		same_1 = same_1 && s0[0] == s1[0];
		same_2 = same_2 && s0[1] == s1[1];
	}

	if (same_1 && same_2) {
		pos = 0;
		len = 3;
	} else if (same_1) {
		pos = 0;
		len = 1;
	} else if (same_2) {
		pos = 1;
		len = 1;
	} else
		return;

	for (i = 0; i < result->nr; i++) {
		char *s = result->items[i].string;
		int length = strlen(s);
		memmove(s + pos, s + pos + len, length - len + 1);
	}
}

static void display(const struct string_list *result)
{
	int i;

	if (column_active(colopts)) {
		struct column_options copts;
		memset(&copts, 0, sizeof(copts));
		copts.padding = 2;
		print_columns(result, colopts, &copts);
		return;
	}

	for (i = 0; i < result->nr; i++) {
		const struct string_list_item *s = result->items + i;

		printf("%s\n", s->string);
	}
}

static int ls_config(const char *var, const char *value, void *cb)
{
	if (starts_with(var, "column."))
		return git_column_config(var, value, "listfiles", &colopts);
	return git_default_config(var, value, cb);
}

int cmd_list_files(int argc, const char **argv, const char *cmd_prefix)
{
	struct string_list result = STRING_LIST_INIT_NODUP;

	setenv(GIT_GLOB_PATHSPECS_ENVIRONMENT, "1", 0);

	if (argc == 2 && !strcmp(argv[1], "-h"))
		usage_with_options(ls_usage, ls_options);

	prefix = cmd_prefix;
	if (prefix)
		prefix_length = strlen(prefix);

	if (read_cache() < 0)
		die(_("index file corrupt"));

	git_config(ls_config, NULL);

	argc = parse_options(argc, argv, prefix, ls_options, ls_usage, 0);

	parse_pathspec(&pathspec, 0,
		       PATHSPEC_PREFER_CWD |
		       (max_depth != -1 ? PATHSPEC_MAXDEPTH_VALID : 0) |
		       PATHSPEC_STRIP_SUBMODULE_SLASH_CHEAP,
		       cmd_prefix, argv);
	pathspec.max_depth = max_depth;
	pathspec.recursive = 1;
	finalize_colopts(&colopts, -1);

	refresh_index(&the_index, REFRESH_QUIET | REFRESH_UNMERGED,
		      &pathspec, NULL, NULL);

	populate_cached_entries(&result, &the_index);
	cleanup_tags(&result);
	display(&result);
	string_list_clear(&result, 0);
	return 0;
}
