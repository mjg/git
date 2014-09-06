#include "cache.h"
#include "config.h"
#include "diff.h"
#include "object-store.h"
#include "repository.h"
#include "commit.h"
#include "commit-reach.h"
#include "tag.h"
#include "graph.h"
#include "log-tree.h"
#include "reflog-walk.h"
#include "refs.h"
#include "string-list.h"
#include "color.h"
#include "gpg-interface.h"
#include "sequencer.h"
#include "line-log.h"
#include "help.h"
#include "interdiff.h"
#include "range-diff.h"
#include "cache-tree.h"
#include "merge-recursive.h"

static struct decoration name_decoration = { "object names" };
static int decoration_loaded;
static int decoration_flags;

static char decoration_colors[][COLOR_MAXLEN] = {
	GIT_COLOR_RESET,
	GIT_COLOR_BOLD_GREEN,	/* REF_LOCAL */
	GIT_COLOR_BOLD_RED,	/* REF_REMOTE */
	GIT_COLOR_BOLD_YELLOW,	/* REF_TAG */
	GIT_COLOR_BOLD_MAGENTA,	/* REF_STASH */
	GIT_COLOR_BOLD_CYAN,	/* REF_HEAD */
	GIT_COLOR_BOLD_BLUE,	/* GRAFTED */
};

static const char *color_decorate_slots[] = {
	[DECORATION_REF_LOCAL]	= "branch",
	[DECORATION_REF_REMOTE] = "remoteBranch",
	[DECORATION_REF_TAG]	= "tag",
	[DECORATION_REF_STASH]	= "stash",
	[DECORATION_REF_HEAD]	= "HEAD",
	[DECORATION_GRAFTED]	= "grafted",
};

static const char *decorate_get_color(int decorate_use_color, enum decoration_type ix)
{
	if (want_color(decorate_use_color))
		return decoration_colors[ix];
	return "";
}

define_list_config_array(color_decorate_slots);

int parse_decorate_color_config(const char *var, const char *slot_name, const char *value)
{
	int slot = LOOKUP_CONFIG(color_decorate_slots, slot_name);
	if (slot < 0)
		return 0;
	if (!value)
		return config_error_nonbool(var);
	return color_parse(value, decoration_colors[slot]);
}

/*
 * log-tree.c uses DIFF_OPT_TST for determining whether to use color
 * for showing the commit sha1, use the same check for --decorate
 */
#define decorate_get_color_opt(o, ix) \
	decorate_get_color((o)->use_color, ix)

void add_name_decoration(enum decoration_type type, const char *name, struct object *obj)
{
	struct name_decoration *res;
	FLEX_ALLOC_STR(res, name, name);
	res->type = type;
	res->next = add_decoration(&name_decoration, obj, res);
}

const struct name_decoration *get_name_decoration(const struct object *obj)
{
	return lookup_decoration(&name_decoration, obj);
}

static int add_ref_decoration(const char *refname, const struct object_id *oid,
			      int flags, void *cb_data)
{
	struct object *obj;
	enum decoration_type type = DECORATION_NONE;
	struct decoration_filter *filter = (struct decoration_filter *)cb_data;

	if (filter && !ref_filter_match(refname,
			      filter->include_ref_pattern,
			      filter->exclude_ref_pattern))
		return 0;

	if (starts_with(refname, git_replace_ref_base)) {
		struct object_id original_oid;
		if (!read_replace_refs)
			return 0;
		if (get_oid_hex(refname + strlen(git_replace_ref_base),
				&original_oid)) {
			warning("invalid replace ref %s", refname);
			return 0;
		}
		obj = parse_object(the_repository, &original_oid);
		if (obj)
			add_name_decoration(DECORATION_GRAFTED, "replaced", obj);
		return 0;
	}

	obj = parse_object(the_repository, oid);
	if (!obj)
		return 0;

	if (starts_with(refname, "refs/heads/"))
		type = DECORATION_REF_LOCAL;
	else if (starts_with(refname, "refs/remotes/"))
		type = DECORATION_REF_REMOTE;
	else if (starts_with(refname, "refs/tags/"))
		type = DECORATION_REF_TAG;
	else if (!strcmp(refname, "refs/stash"))
		type = DECORATION_REF_STASH;
	else if (!strcmp(refname, "HEAD"))
		type = DECORATION_REF_HEAD;

	add_name_decoration(type, refname, obj);
	while (obj->type == OBJ_TAG) {
		obj = ((struct tag *)obj)->tagged;
		if (!obj)
			break;
		if (!obj->parsed)
			parse_object(the_repository, &obj->oid);
		add_name_decoration(DECORATION_REF_TAG, refname, obj);
	}
	return 0;
}

static int add_graft_decoration(const struct commit_graft *graft, void *cb_data)
{
	struct commit *commit = lookup_commit(the_repository, &graft->oid);
	if (!commit)
		return 0;
	add_name_decoration(DECORATION_GRAFTED, "grafted", &commit->object);
	return 0;
}

void load_ref_decorations(struct decoration_filter *filter, int flags)
{
	if (!decoration_loaded) {
		if (filter) {
			struct string_list_item *item;
			for_each_string_list_item(item, filter->exclude_ref_pattern) {
				normalize_glob_ref(item, NULL, item->string);
			}
			for_each_string_list_item(item, filter->include_ref_pattern) {
				normalize_glob_ref(item, NULL, item->string);
			}
		}
		decoration_loaded = 1;
		decoration_flags = flags;
		for_each_ref(add_ref_decoration, filter);
		head_ref(add_ref_decoration, filter);
		for_each_commit_graft(add_graft_decoration, filter);
	}
}

static void show_parents(struct commit *commit, int abbrev, FILE *file)
{
	struct commit_list *p;
	for (p = commit->parents; p ; p = p->next) {
		struct commit *parent = p->item;
		fprintf(file, " %s", find_unique_abbrev(&parent->object.oid, abbrev));
	}
}

static void show_children(struct rev_info *opt, struct commit *commit, int abbrev)
{
	struct commit_list *p = lookup_decoration(&opt->children, &commit->object);
	for ( ; p; p = p->next) {
		fprintf(opt->diffopt.file, " %s", find_unique_abbrev(&p->item->object.oid, abbrev));
	}
}

/*
 * Do we have HEAD in the output, and also the branch it points at?
 * If so, find that decoration entry for that current branch.
 */
static const struct name_decoration *current_pointed_by_HEAD(const struct name_decoration *decoration)
{
	const struct name_decoration *list, *head = NULL;
	const char *branch_name = NULL;
	int rru_flags;

	/* First find HEAD */
	for (list = decoration; list; list = list->next)
		if (list->type == DECORATION_REF_HEAD) {
			head = list;
			break;
		}
	if (!head)
		return NULL;

	/* Now resolve and find the matching current branch */
	branch_name = resolve_ref_unsafe("HEAD", 0, NULL, &rru_flags);
	if (!branch_name || !(rru_flags & REF_ISSYMREF))
		return NULL;

	if (!starts_with(branch_name, "refs/"))
		return NULL;

	/* OK, do we have that ref in the list? */
	for (list = decoration; list; list = list->next)
		if ((list->type == DECORATION_REF_LOCAL) &&
		    !strcmp(branch_name, list->name)) {
			return list;
		}

	return NULL;
}

static void show_name(struct strbuf *sb, const struct name_decoration *decoration)
{
	if (decoration_flags == DECORATE_SHORT_REFS)
		strbuf_addstr(sb, prettify_refname(decoration->name));
	else
		strbuf_addstr(sb, decoration->name);
}

/*
 * The caller makes sure there is no funny color before calling.
 * format_decorations_extended makes sure the same after return.
 */
void format_decorations_extended(struct strbuf *sb,
			const struct commit *commit,
			int use_color,
			const char *prefix,
			const char *separator,
			const char *suffix)
{
	const struct name_decoration *decoration;
	const struct name_decoration *current_and_HEAD;
	const char *color_commit =
		diff_get_color(use_color, DIFF_COMMIT);
	const char *color_reset =
		decorate_get_color(use_color, DECORATION_NONE);

	decoration = get_name_decoration(&commit->object);
	if (!decoration)
		return;

	current_and_HEAD = current_pointed_by_HEAD(decoration);
	while (decoration) {
		/*
		 * When both current and HEAD are there, only
		 * show HEAD->current where HEAD would have
		 * appeared, skipping the entry for current.
		 */
		if (decoration != current_and_HEAD) {
			strbuf_addstr(sb, color_commit);
			strbuf_addstr(sb, prefix);
			strbuf_addstr(sb, color_reset);
			strbuf_addstr(sb, decorate_get_color(use_color, decoration->type));
			if (decoration->type == DECORATION_REF_TAG)
				strbuf_addstr(sb, "tag: ");

			show_name(sb, decoration);

			if (current_and_HEAD &&
			    decoration->type == DECORATION_REF_HEAD) {
				strbuf_addstr(sb, " -> ");
				strbuf_addstr(sb, color_reset);
				strbuf_addstr(sb, decorate_get_color(use_color, current_and_HEAD->type));
				show_name(sb, current_and_HEAD);
			}
			strbuf_addstr(sb, color_reset);

			prefix = separator;
		}
		decoration = decoration->next;
	}
	strbuf_addstr(sb, color_commit);
	strbuf_addstr(sb, suffix);
	strbuf_addstr(sb, color_reset);
}

void show_decorations(struct rev_info *opt, struct commit *commit)
{
	struct strbuf sb = STRBUF_INIT;

	if (opt->sources) {
		char **slot = revision_sources_peek(opt->sources, commit);

		if (slot && *slot)
			fprintf(opt->diffopt.file, "\t%s", *slot);
	}
	if (!opt->show_decorations)
		return;
	format_decorations(&sb, commit, opt->diffopt.use_color);
	fputs(sb.buf, opt->diffopt.file);
	strbuf_release(&sb);
}

static unsigned int digits_in_number(unsigned int number)
{
	unsigned int i = 10, result = 1;
	while (i <= number) {
		i *= 10;
		result++;
	}
	return result;
}

void fmt_output_subject(struct strbuf *filename,
			const char *subject,
			struct rev_info *info)
{
	const char *suffix = info->patch_suffix;
	int nr = info->nr;
	int start_len = filename->len;
	int max_len = start_len + FORMAT_PATCH_NAME_MAX - (strlen(suffix) + 1);

	if (0 < info->reroll_count)
		strbuf_addf(filename, "v%d-", info->reroll_count);
	strbuf_addf(filename, "%04d-%s", nr, subject);

	if (max_len < filename->len)
		strbuf_setlen(filename, max_len);
	strbuf_addstr(filename, suffix);
}

void fmt_output_commit(struct strbuf *filename,
		       struct commit *commit,
		       struct rev_info *info)
{
	struct pretty_print_context ctx = {0};
	struct strbuf subject = STRBUF_INIT;

	format_commit_message(commit, "%f", &subject, &ctx);
	fmt_output_subject(filename, subject.buf, info);
	strbuf_release(&subject);
}

void fmt_output_email_subject(struct strbuf *sb, struct rev_info *opt)
{
	if (opt->total > 0) {
		strbuf_addf(sb, "Subject: [%s%s%0*d/%d] ",
			    opt->subject_prefix,
			    *opt->subject_prefix ? " " : "",
			    digits_in_number(opt->total),
			    opt->nr, opt->total);
	} else if (opt->total == 0 && opt->subject_prefix && *opt->subject_prefix) {
		strbuf_addf(sb, "Subject: [%s] ",
			    opt->subject_prefix);
	} else {
		strbuf_addstr(sb, "Subject: ");
	}
}

void log_write_email_headers(struct rev_info *opt, struct commit *commit,
			     const char **extra_headers_p,
			     int *need_8bit_cte_p,
			     int maybe_multipart)
{
	const char *extra_headers = opt->extra_headers;
	const char *name = oid_to_hex(opt->zero_commit ?
				      &null_oid : &commit->object.oid);

	*need_8bit_cte_p = 0; /* unknown */

	fprintf(opt->diffopt.file, "From %s Mon Sep 17 00:00:00 2001\n", name);
	graph_show_oneline(opt->graph);
	if (opt->message_id) {
		fprintf(opt->diffopt.file, "Message-Id: <%s>\n", opt->message_id);
		graph_show_oneline(opt->graph);
	}
	if (opt->ref_message_ids && opt->ref_message_ids->nr > 0) {
		int i, n;
		n = opt->ref_message_ids->nr;
		fprintf(opt->diffopt.file, "In-Reply-To: <%s>\n", opt->ref_message_ids->items[n-1].string);
		for (i = 0; i < n; i++)
			fprintf(opt->diffopt.file, "%s<%s>\n", (i > 0 ? "\t" : "References: "),
			       opt->ref_message_ids->items[i].string);
		graph_show_oneline(opt->graph);
	}
	if (opt->mime_boundary && maybe_multipart) {
		static struct strbuf subject_buffer = STRBUF_INIT;
		static struct strbuf buffer = STRBUF_INIT;
		struct strbuf filename =  STRBUF_INIT;
		*need_8bit_cte_p = -1; /* NEVER */

		strbuf_reset(&subject_buffer);
		strbuf_reset(&buffer);

		strbuf_addf(&subject_buffer,
			 "%s"
			 "MIME-Version: 1.0\n"
			 "Content-Type: multipart/mixed;"
			 " boundary=\"%s%s\"\n"
			 "\n"
			 "This is a multi-part message in MIME "
			 "format.\n"
			 "--%s%s\n"
			 "Content-Type: text/plain; "
			 "charset=UTF-8; format=fixed\n"
			 "Content-Transfer-Encoding: 8bit\n\n",
			 extra_headers ? extra_headers : "",
			 mime_boundary_leader, opt->mime_boundary,
			 mime_boundary_leader, opt->mime_boundary);
		extra_headers = subject_buffer.buf;

		if (opt->numbered_files)
			strbuf_addf(&filename, "%d", opt->nr);
		else
			fmt_output_commit(&filename, commit, opt);
		strbuf_addf(&buffer,
			 "\n--%s%s\n"
			 "Content-Type: text/x-patch;"
			 " name=\"%s\"\n"
			 "Content-Transfer-Encoding: 8bit\n"
			 "Content-Disposition: %s;"
			 " filename=\"%s\"\n\n",
			 mime_boundary_leader, opt->mime_boundary,
			 filename.buf,
			 opt->no_inline ? "attachment" : "inline",
			 filename.buf);
		opt->diffopt.stat_sep = buffer.buf;
		strbuf_release(&filename);
	}
	*extra_headers_p = extra_headers;
}

static void show_sig_lines(struct rev_info *opt, int status, const char *bol)
{
	const char *color, *reset, *eol;

	color = diff_get_color_opt(&opt->diffopt,
				   status ? DIFF_WHITESPACE : DIFF_FRAGINFO);
	reset = diff_get_color_opt(&opt->diffopt, DIFF_RESET);
	while (*bol) {
		eol = strchrnul(bol, '\n');
		fprintf(opt->diffopt.file, "%s%.*s%s%s", color, (int)(eol - bol), bol, reset,
		       *eol ? "\n" : "");
		graph_show_oneline(opt->graph);
		bol = (*eol) ? (eol + 1) : eol;
	}
}

static void show_signature(struct rev_info *opt, struct commit *commit)
{
	struct strbuf payload = STRBUF_INIT;
	struct strbuf signature = STRBUF_INIT;
	struct strbuf gpg_output = STRBUF_INIT;
	int status;

	if (parse_signed_commit(commit, &payload, &signature) <= 0)
		goto out;

	status = verify_signed_buffer(payload.buf, payload.len,
				      signature.buf, signature.len,
				      &gpg_output, NULL);
	if (status && !gpg_output.len)
		strbuf_addstr(&gpg_output, "No signature\n");

	show_sig_lines(opt, status, gpg_output.buf);

 out:
	strbuf_release(&gpg_output);
	strbuf_release(&payload);
	strbuf_release(&signature);
}

static int which_parent(const struct object_id *oid, const struct commit *commit)
{
	int nth;
	const struct commit_list *parent;

	for (nth = 0, parent = commit->parents; parent; parent = parent->next) {
		if (oideq(&parent->item->object.oid, oid))
			return nth;
		nth++;
	}
	return -1;
}

static int is_common_merge(const struct commit *commit)
{
	return (commit->parents
		&& commit->parents->next
		&& !commit->parents->next->next);
}

static int show_one_mergetag(struct commit *commit,
			     struct commit_extra_header *extra,
			     void *data)
{
	struct rev_info *opt = (struct rev_info *)data;
	struct object_id oid;
	struct tag *tag;
	struct strbuf verify_message;
	int status, nth;
	size_t payload_size, gpg_message_offset;

	hash_object_file(extra->value, extra->len, type_name(OBJ_TAG), &oid);
	tag = lookup_tag(the_repository, &oid);
	if (!tag)
		return -1; /* error message already given */

	strbuf_init(&verify_message, 256);
	if (parse_tag_buffer(the_repository, tag, extra->value, extra->len))
		strbuf_addstr(&verify_message, "malformed mergetag\n");
	else if (is_common_merge(commit) &&
		 oideq(&tag->tagged->oid,
		       &commit->parents->next->item->object.oid))
		strbuf_addf(&verify_message,
			    "merged tag '%s'\n", tag->tag);
	else if ((nth = which_parent(&tag->tagged->oid, commit)) < 0)
		strbuf_addf(&verify_message, "tag %s names a non-parent %s\n",
				    tag->tag, tag->tagged->oid.hash);
	else
		strbuf_addf(&verify_message,
			    "parent #%d, tagged '%s'\n", nth + 1, tag->tag);
	gpg_message_offset = verify_message.len;

	payload_size = parse_signature(extra->value, extra->len);
	status = -1;
	if (extra->len > payload_size) {
		/* could have a good signature */
		if (!verify_signed_buffer(extra->value, payload_size,
					  extra->value + payload_size,
					  extra->len - payload_size,
					  &verify_message, NULL))
			status = 0; /* good */
		else if (verify_message.len <= gpg_message_offset)
			strbuf_addstr(&verify_message, "No signature\n");
		/* otherwise we couldn't verify, which is shown as bad */
	}

	show_sig_lines(opt, status, verify_message.buf);
	strbuf_release(&verify_message);
	return 0;
}

static int show_mergetag(struct rev_info *opt, struct commit *commit)
{
	return for_each_mergetag(show_one_mergetag, commit, opt);
}

static void next_commentary_block(struct rev_info *opt, struct strbuf *sb)
{
	const char *x = opt->shown_dashes ? "\n" : "---\n";
	if (sb)
		strbuf_addstr(sb, x);
	else
		fputs(x, opt->diffopt.file);
	opt->shown_dashes = 1;
}

void show_log(struct rev_info *opt)
{
	struct strbuf msgbuf = STRBUF_INIT;
	struct log_info *log = opt->loginfo;
	struct commit *commit = log->commit, *parent = log->parent;
	int abbrev_commit = opt->abbrev_commit ? opt->abbrev : the_hash_algo->hexsz;
	const char *extra_headers = opt->extra_headers;
	struct pretty_print_context ctx = {0};

	opt->loginfo = NULL;
	if (!opt->verbose_header) {
		graph_show_commit(opt->graph);

		if (!opt->graph)
			put_revision_mark(opt, commit);
		fputs(find_unique_abbrev(&commit->object.oid, abbrev_commit), opt->diffopt.file);
		if (opt->print_parents)
			show_parents(commit, abbrev_commit, opt->diffopt.file);
		if (opt->children.name)
			show_children(opt, commit, abbrev_commit);
		show_decorations(opt, commit);
		if (opt->graph && !graph_is_commit_finished(opt->graph)) {
			putc('\n', opt->diffopt.file);
			graph_show_remainder(opt->graph);
		}
		putc(opt->diffopt.line_termination, opt->diffopt.file);
		return;
	}

	/*
	 * If use_terminator is set, we already handled any record termination
	 * at the end of the last record.
	 * Otherwise, add a diffopt.line_termination character before all
	 * entries but the first.  (IOW, as a separator between entries)
	 */
	if (opt->shown_one && !opt->use_terminator) {
		/*
		 * If entries are separated by a newline, the output
		 * should look human-readable.  If the last entry ended
		 * with a newline, print the graph output before this
		 * newline.  Otherwise it will end up as a completely blank
		 * line and will look like a gap in the graph.
		 *
		 * If the entry separator is not a newline, the output is
		 * primarily intended for programmatic consumption, and we
		 * never want the extra graph output before the entry
		 * separator.
		 */
		if (opt->diffopt.line_termination == '\n' &&
		    !opt->missing_newline)
			graph_show_padding(opt->graph);
		putc(opt->diffopt.line_termination, opt->diffopt.file);
	}
	opt->shown_one = 1;

	/*
	 * If the history graph was requested,
	 * print the graph, up to this commit's line
	 */
	graph_show_commit(opt->graph);

	/*
	 * Print header line of header..
	 */

	if (cmit_fmt_is_mail(opt->commit_format)) {
		log_write_email_headers(opt, commit, &extra_headers,
					&ctx.need_8bit_cte, 1);
		ctx.rev = opt;
		ctx.print_email_subject = 1;
	} else if (opt->commit_format != CMIT_FMT_USERFORMAT) {
		fputs(diff_get_color_opt(&opt->diffopt, DIFF_COMMIT), opt->diffopt.file);
		if (opt->commit_format != CMIT_FMT_ONELINE)
			fputs("commit ", opt->diffopt.file);

		if (!opt->graph)
			put_revision_mark(opt, commit);
		fputs(find_unique_abbrev(&commit->object.oid,
					 abbrev_commit),
		      opt->diffopt.file);
		if (opt->print_parents)
			show_parents(commit, abbrev_commit, opt->diffopt.file);
		if (opt->children.name)
			show_children(opt, commit, abbrev_commit);
		if (parent)
			fprintf(opt->diffopt.file, " (from %s)",
			       find_unique_abbrev(&parent->object.oid, abbrev_commit));
		fputs(diff_get_color_opt(&opt->diffopt, DIFF_RESET), opt->diffopt.file);
		show_decorations(opt, commit);
		if (opt->commit_format == CMIT_FMT_ONELINE) {
			putc(' ', opt->diffopt.file);
		} else {
			putc('\n', opt->diffopt.file);
			graph_show_oneline(opt->graph);
		}
		if (opt->reflog_info) {
			/*
			 * setup_revisions() ensures that opt->reflog_info
			 * and opt->graph cannot both be set,
			 * so we don't need to worry about printing the
			 * graph info here.
			 */
			show_reflog_message(opt->reflog_info,
					    opt->commit_format == CMIT_FMT_ONELINE,
					    &opt->date_mode,
					    opt->date_mode_explicit);
			if (opt->commit_format == CMIT_FMT_ONELINE)
				return;
		}
	}

	if (opt->show_signature) {
		show_signature(opt, commit);
		show_mergetag(opt, commit);
	}

	if (opt->show_notes) {
		int raw;
		struct strbuf notebuf = STRBUF_INIT;

		raw = (opt->commit_format == CMIT_FMT_USERFORMAT);
		format_display_notes(&commit->object.oid, &notebuf,
				     get_log_output_encoding(), raw);
		ctx.notes_message = strbuf_detach(&notebuf, NULL);
	}

	/*
	 * And then the pretty-printed message itself
	 */
	if (ctx.need_8bit_cte >= 0 && opt->add_signoff)
		ctx.need_8bit_cte =
			has_non_ascii(fmt_name(WANT_COMMITTER_IDENT));
	ctx.date_mode = opt->date_mode;
	ctx.date_mode_explicit = opt->date_mode_explicit;
	ctx.abbrev = opt->diffopt.abbrev;
	ctx.after_subject = extra_headers;
	ctx.preserve_subject = opt->preserve_subject;
	ctx.reflog_info = opt->reflog_info;
	ctx.fmt = opt->commit_format;
	ctx.mailmap = opt->mailmap;
	ctx.color = opt->diffopt.use_color;
	ctx.expand_tabs_in_log = opt->expand_tabs_in_log;
	ctx.output_encoding = get_log_output_encoding();
	ctx.rev = opt;
	if (opt->from_ident.mail_begin && opt->from_ident.name_begin)
		ctx.from_ident = &opt->from_ident;
	if (opt->graph)
		ctx.graph_width = graph_width(opt->graph);
	pretty_print_commit(&ctx, commit, &msgbuf);

	if (opt->add_signoff)
		append_signoff(&msgbuf, 0, APPEND_SIGNOFF_DEDUP);

	if ((ctx.fmt != CMIT_FMT_USERFORMAT) &&
	    ctx.notes_message && *ctx.notes_message) {
		if (cmit_fmt_is_mail(ctx.fmt))
			next_commentary_block(opt, &msgbuf);
		strbuf_addstr(&msgbuf, ctx.notes_message);
	}

	if (opt->show_log_size) {
		fprintf(opt->diffopt.file, "log size %i\n", (int)msgbuf.len);
		graph_show_oneline(opt->graph);
	}

	/*
	 * Set opt->missing_newline if msgbuf doesn't
	 * end in a newline (including if it is empty)
	 */
	if (!msgbuf.len || msgbuf.buf[msgbuf.len - 1] != '\n')
		opt->missing_newline = 1;
	else
		opt->missing_newline = 0;

	graph_show_commit_msg(opt->graph, opt->diffopt.file, &msgbuf);
	if (opt->use_terminator && !commit_format_is_empty(opt->commit_format)) {
		if (!opt->missing_newline)
			graph_show_padding(opt->graph);
		putc(opt->diffopt.line_termination, opt->diffopt.file);
	}

	strbuf_release(&msgbuf);
	free(ctx.notes_message);

	if (cmit_fmt_is_mail(ctx.fmt) && opt->idiff_oid1) {
		struct diff_queue_struct dq;

		memcpy(&dq, &diff_queued_diff, sizeof(diff_queued_diff));
		DIFF_QUEUE_CLEAR(&diff_queued_diff);

		next_commentary_block(opt, NULL);
		fprintf_ln(opt->diffopt.file, "%s", opt->idiff_title);
		show_interdiff(opt, 2);

		memcpy(&diff_queued_diff, &dq, sizeof(diff_queued_diff));
	}

	if (cmit_fmt_is_mail(ctx.fmt) && opt->rdiff1) {
		struct diff_queue_struct dq;
		struct diff_options opts;

		memcpy(&dq, &diff_queued_diff, sizeof(diff_queued_diff));
		DIFF_QUEUE_CLEAR(&diff_queued_diff);

		next_commentary_block(opt, NULL);
		fprintf_ln(opt->diffopt.file, "%s", opt->rdiff_title);
		/*
		 * Pass minimum required diff-options to range-diff; others
		 * can be added later if deemed desirable.
		 */
		diff_setup(&opts);
		opts.file = opt->diffopt.file;
		opts.use_color = opt->diffopt.use_color;
		diff_setup_done(&opts);
		show_range_diff(opt->rdiff1, opt->rdiff2,
				opt->creation_factor, 1, &opts);

		memcpy(&diff_queued_diff, &dq, sizeof(diff_queued_diff));
	}
}

int log_tree_diff_flush(struct rev_info *opt)
{
	opt->shown_dashes = 0;
	diffcore_std(&opt->diffopt);

	if (diff_queue_is_empty()) {
		int saved_fmt = opt->diffopt.output_format;
		opt->diffopt.output_format = DIFF_FORMAT_NO_OUTPUT;
		diff_flush(&opt->diffopt);
		opt->diffopt.output_format = saved_fmt;
		return 0;
	}

	if (opt->loginfo && !opt->no_commit_id) {
		show_log(opt);
		if ((opt->diffopt.output_format & ~DIFF_FORMAT_NO_OUTPUT) &&
		    opt->verbose_header &&
		    opt->commit_format != CMIT_FMT_ONELINE &&
		    !commit_format_is_empty(opt->commit_format)) {
			/*
			 * When showing a verbose header (i.e. log message),
			 * and not in --pretty=oneline format, we would want
			 * an extra newline between the end of log and the
			 * diff/diffstat output for readability.
			 */
			int pch = DIFF_FORMAT_DIFFSTAT | DIFF_FORMAT_PATCH;
			if (opt->diffopt.output_prefix) {
				struct strbuf *msg = NULL;
				msg = opt->diffopt.output_prefix(&opt->diffopt,
					opt->diffopt.output_prefix_data);
				fwrite(msg->buf, msg->len, 1, opt->diffopt.file);
			}

			/*
			 * We may have shown three-dashes line early
			 * between generated commentary (notes, etc.)
			 * and the log message, in which case we only
			 * want a blank line after the commentary
			 * without (an extra) three-dashes line.
			 * Otherwise, we show the three-dashes line if
			 * we are showing the patch with diffstat, but
			 * in that case, there is no extra blank line
			 * after the three-dashes line.
			 */
			if (!opt->shown_dashes &&
			    (pch & opt->diffopt.output_format) == pch)
				fprintf(opt->diffopt.file, "---");
			putc('\n', opt->diffopt.file);
		}
	}
	diff_flush(&opt->diffopt);
	return 1;
}

static int do_diff_combined(struct rev_info *opt, struct commit *commit)
{
	diff_tree_combined_merge(commit, opt);
	return !opt->loginfo;
}

/*
 * Helpers for make_asymmetric_conflict_entries() below.
 */
static char *load_cache_entry_blob(struct cache_entry *entry,
				   unsigned long *size)
{
	enum object_type type;
	void *data;

	if (!entry)
		return NULL;

	data = read_object_file(&entry->oid, &type, size);
	if (type != OBJ_BLOB)
		die("BUG: load_cache_entry_blob for non-blob");

	return data;
}

static void strbuf_append_cache_entry_blob(struct strbuf *sb,
					   struct cache_entry *entry)
{
	unsigned long size;
	char *data = load_cache_entry_blob(entry, &size);;

	if (!data)
		return;

	strbuf_add(sb, data, size);
	free(data);
}

static void assemble_conflict_entry(struct strbuf *sb,
				    const char *branch1,
				    const char *branch2,
				    struct cache_entry *entry1,
				    struct cache_entry *entry2)
{
	strbuf_addf(sb, "<<<<<<< %s\n", branch1);
	strbuf_append_cache_entry_blob(sb, entry1);
	strbuf_addstr(sb, "=======\n");
	strbuf_append_cache_entry_blob(sb, entry2);
	strbuf_addf(sb, ">>>>>>> %s\n", branch2);
}

/*
 * For --remerge-diff, we need conflicted (<<<<<<< ... >>>>>>>)
 * representations of as many conflicts as possible.  Default conflict
 * generation only applies to files that have all three stages.
 *
 * This function generates conflict hunk representations for files
 * that have only one of stage 2 or 3.  The corresponding side in the
 * conflict hunk format will be empty.  A stage 1, if any, will be
 * dropped in the process.
 */
static void make_asymmetric_conflict_entries(struct index_state *istate,
					     const char *branch1,
					     const char *branch2)
{
	int o = 0, i = 0;

	/*
	 * NEEDSWORK: we trample all over the cache below, so we need
	 * to set up the name hash early, before modifying it.  And
	 * after that we cannot free any cache entries, because they
	 * remain hashed even if deleted.  Sigh.
	 */
	lazy_init_name_hash(istate, 1);

	/*
	 * The loop always starts with 'i' pointing at the first entry
	 * for a pathname.
	 */
	while (i < istate->cache_nr) {
		struct cache_entry *ce;
		struct cache_entry *stage1 = NULL;
		struct cache_entry *stage2 = NULL;
		struct cache_entry *stage3 = NULL;
		struct cache_entry *new_ce = NULL;
		struct strbuf content = STRBUF_INIT;
		struct object_id oid;

		assert(o <= i);

		ce = istate->cache[i];

		/*
		 * Pass through stage 0 and submodules unchanged, we
		 * don't know how to handle them.
		 */
		if (ce_stage(ce) == 0
		    || S_ISGITLINK(ce->ce_mode)) {
			istate->cache[o++] = ce;
			i++;
			continue;
		}

		/*
		 * Collect the stages we have.  Point 'i' past the
		 * entry.
		 */
		if (/* i < istate->cache_nr && */
		    !strcmp(ce->name, istate->cache[i]->name) &&
		    ce_stage(istate->cache[i]) == 1)
			stage1 = istate->cache[i++];

		if (i < istate->cache_nr &&
		    !strcmp(ce->name, istate->cache[i]->name) &&
		    ce_stage(istate->cache[i]) == 2)
			stage2 = istate->cache[i++];

		if (i < istate->cache_nr &&
		    !strcmp(ce->name, istate->cache[i]->name) &&
		    ce_stage(istate->cache[i]) == 3)
			stage3 = istate->cache[i++];

		if (!stage2 && !stage3)
			die("BUG: merging resulted in conflict with neither "
			    "stage 2 nor 3");

		if (index_dir_exists(istate, ce->name, ce->ce_namelen)) {
			/*
			 * If a conflicting directory for this entry exists,
			 * we can drop it:
			 *
			 * In the face of a file/directory conflict,
			 * merge-recursive
			 * - puts the file at stage >0 as usual
			 * - also attempts to check out the file as
			 *   'file~side' where side is the sha1 of the commit
			 *   the file came from, to avoid colliding with the
			 *   directory
			 *
			 * But we have requested that files go to the index
			 * instead of the worktree, so by the time we get
			 * here, we have both stage>0 'file' from ordinary
			 * merging and a stage=0 'file~side' from the "write
			 * all files to index".
			 *
			 * We need to remove one of them.  Currently we ditch
			 * the 'file' entry because it's easier to detect.
			 * This amounts to always renaming the file to make
			 * room for the directory.
			 *
			 * NEEDSWORK: Two options:
			 *
			 * - If the merge result kept the file, it would be
			 *   better to rename the _directory_ to make room for
			 *   the file, so that filenames match between the
			 *   result and the re-merge.
			 *
			 * - Or we could avoid going through a tree, since the
			 *   index can represent (though it's not "legal") a
			 *   file/directory collision just fine.
			 */
		} else {
			/*
			 * Otherwise, there is room for a file entry
			 * at stage 0.  It has fake-conflict content,
			 * but its mode is the same.
			 */

			assemble_conflict_entry(&content,
						branch1, branch2,
						stage2, stage3);
			if (write_object_file(content.buf, content.len,
					    type_name(OBJ_BLOB), &oid))
				die("write_object_file failed");
			strbuf_release(&content);

			new_ce = make_cache_entry(istate, ce->ce_mode, &oid, ce->name, 0, 0);
			new_ce->ce_flags = ce->ce_flags & ~CE_STAGEMASK;
			istate->cache[o++] = new_ce;
			add_name_hash(istate, new_ce);
		}

		if (stage1)
			remove_name_hash(istate, stage1);
		if (stage2)
			remove_name_hash(istate, stage2);
		if (stage3)
			remove_name_hash(istate, stage3);
		discard_cache_entry(stage1);
		discard_cache_entry(stage2);
		discard_cache_entry(stage3);
	}

	istate->cache_nr = o;
}

/*
 * --remerge-diff doesn't currently handle entries that cannot be
 * turned into a stage0 conflicted-file format blob.  So this routine
 * clears the corresponding entries from the index.  This is
 * suboptimal; we should eventually handle them _somehow_.
*/
static void drop_non_stage0(struct index_state *istate)
{
	int o = 0, i = 0;

	while (i < istate->cache_nr) {
		struct cache_entry *ce = istate->cache[i];
		const char *name;

		if (!ce_stage(ce)) {
			istate->cache[o++] = istate->cache[i++];
			continue;
		}

		name = ce->name;

		printf("Cannot handle stage %d entry '%s', skipping\n",
		       ce_stage(ce), name);
		i++;

		while (i < istate->cache_nr && !strcmp(name, istate->cache[i]->name))
			discard_cache_entry(istate->cache[i++]);

		free(ce);
	}

	istate->cache_nr = o;
}

static int do_diff_remerge(struct rev_info *opt, struct commit *commit)
{
	struct commit_list *merge_bases;
	struct commit *result, *parent1, *parent2;
	struct merge_options o;
	char *branch1, *branch2;
	struct cache_tree *orig_cache_tree;

	/*
	 * We show the log message early to avoid headaches later.  In
	 * general we need to run this before printing anything in
	 * this routine.
	 */
	if (opt->loginfo && !opt->no_commit_id) {
		show_log(opt);

		if (opt->verbose_header && opt->diffopt.output_format)
			printf("%s%c", diff_line_prefix(&opt->diffopt),
			       opt->diffopt.line_termination);
	}

	if (commit->parents->next->next) {
		printf("--remerge-diff not supported for octopus merges.\n");
		return !opt->loginfo;
	}

	parent1 = commit->parents->item;
	parent2 = commit->parents->next->item;
	parse_commit(parent1);
	parse_commit(parent2);
	branch1 = xstrdup(sha1_to_hex(parent1->object.oid.hash));
	branch2 = xstrdup(sha1_to_hex(parent2->object.oid.hash));

	merge_bases = get_octopus_merge_bases(commit->parents);
	init_merge_options(&o, opt->repo);
	o.verbosity = -1;
	o.no_worktree = 1;
	o.conflicts_in_index = 1;
	o.use_ondisk_index = 0;
	o.branch1 = branch1;
	o.branch2 = branch2;
	merge_recursive(&o, parent1, parent2, merge_bases, &result);

	make_asymmetric_conflict_entries(opt->repo->index, branch1, branch2);
	drop_non_stage0(opt->repo->index);

	free(branch1);
	free(branch2);

	orig_cache_tree = opt->repo->index->cache_tree;
	opt->repo->index->cache_tree = cache_tree();
	if (cache_tree_update(opt->repo->index, WRITE_TREE_SILENT) < 0) {
		printf("BUG: merge conflicts not fully folded, cannot diff.\n");
		return !opt->loginfo;
	}

	diff_tree_oid(&opt->repo->index->cache_tree->oid, get_commit_tree_oid(commit),
		       "", &opt->diffopt);
	log_tree_diff_flush(opt);

	cache_tree_free(&opt->repo->index->cache_tree);
	opt->repo->index->cache_tree = orig_cache_tree;

	return !opt->loginfo;
}

/*
 * Show the diff of a commit.
 *
 * Return true if we printed any log info messages
 */
static int log_tree_diff(struct rev_info *opt, struct commit *commit, struct log_info *log)
{
	int showed_log;
	struct commit_list *parents;
	struct object_id *oid;

	if (!opt->diff && !opt->diffopt.flags.exit_with_status)
		return 0;

	parse_commit_or_die(commit);
	oid = get_commit_tree_oid(commit);

	/* Root commit? */
	parents = get_saved_parents(opt, commit);
	if (!parents) {
		if (opt->show_root_diff) {
			diff_root_tree_oid(oid, "", &opt->diffopt);
			log_tree_diff_flush(opt);
		}
		return !opt->loginfo;
	}

	/* More than one parent? */
	if (parents && parents->next) {
		if (opt->merge_diff_mode == MERGE_DIFF_IGNORE)
			return 0;
		else if (merge_diff_mode_is_any_combined(opt))
			return do_diff_combined(opt, commit);
		else if (opt->merge_diff_mode == MERGE_DIFF_REMERGE)
			return do_diff_remerge(opt, commit);
		else if (opt->first_parent_only) {
			/*
			 * Generate merge log entry only for the first
			 * parent, showing summary diff of the others
			 * we merged _in_.
			 */
			parse_commit_or_die(parents->item);
			diff_tree_oid(get_commit_tree_oid(parents->item),
				      oid, "", &opt->diffopt);
			log_tree_diff_flush(opt);
			return !opt->loginfo;
		}

		/* If we show individual diffs, show the parent info */
		log->parent = parents->item;
	}

	showed_log = 0;
	for (;;) {
		struct commit *parent = parents->item;

		parse_commit_or_die(parent);
		diff_tree_oid(get_commit_tree_oid(parent),
			      oid, "", &opt->diffopt);
		log_tree_diff_flush(opt);

		showed_log |= !opt->loginfo;

		/* Set up the log info for the next parent, if any.. */
		parents = parents->next;
		if (!parents)
			break;
		log->parent = parents->item;
		opt->loginfo = log;
	}
	return showed_log;
}

int log_tree_commit(struct rev_info *opt, struct commit *commit)
{
	struct log_info log;
	int shown, close_file = opt->diffopt.close_file;

	log.commit = commit;
	log.parent = NULL;
	opt->loginfo = &log;
	opt->diffopt.close_file = 0;

	if (opt->line_level_traverse)
		return line_log_print(opt, commit);

	if (opt->track_linear && !opt->linear && !opt->reverse_output_stage)
		fprintf(opt->diffopt.file, "\n%s\n", opt->break_bar);
	shown = log_tree_diff(opt, commit, &log);
	if (!shown && opt->loginfo && opt->always_show_header) {
		log.parent = NULL;
		show_log(opt);
		shown = 1;
	}
	if (opt->track_linear && !opt->linear && opt->reverse_output_stage)
		fprintf(opt->diffopt.file, "\n%s\n", opt->break_bar);
	opt->loginfo = NULL;
	maybe_flush_or_die(opt->diffopt.file, "stdout");
	if (close_file)
		fclose(opt->diffopt.file);
	return shown;
}
