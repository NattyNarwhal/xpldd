/*
 * xpldd: cross-platform ELF ldd
 *
 * Copyright (C) 2020 Calvin Buckley
 */
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace std;

extern "C" {
	// getopt, open/close
	#include <fcntl.h>
	#include <unistd.h>
	// libelf
	#include <libelf.h>
	#include <gelf.h>
}

static void usage(string argv0)
{
	cerr << "usage: " << argv0 << " [-n] [-P path_prefix] [-R rpath_entry..] [elf..]\n";
	cerr << "\t-n: no recursion (optional)\n";
	cerr << "\t-R rpath_entry: add rpath entry (optional, useful if binaries lack them)\n";
	cerr << "\t-P path_prefix: string to prefix rpaths with before resolution (optional, useful for chroots)\n";
	cerr << "and takes at least one ELF file to operate on\n";
}

static string resolve_symbol(string& name, vector<string>& rpaths, string& prefix)
{
	if (name[0] == '/') {
		return name;
	}
	for (size_t i = 0; i < rpaths.size(); i++) {
		filesystem::path name_path(name);
		filesystem::path dir_path(prefix + rpaths[i]);
		auto full_path = dir_path / name_path;
		if (filesystem::exists(full_path)) {
			return full_path;
		}
	}
	return name;
}

static bool handle_dynamic(Elf *e, Elf_Scn *scn, GElf_Shdr *shdr,
		vector<string>& unresolved,
		vector<string>& rpath)
{
	size_t shstrndx;
	if (elf_getshdrstrndx (e, &shstrndx) < 0) {
		cerr << "elf_getshdrstrndx\n";
		return false;
	}
	Elf_Data *data = elf_getdata (scn, nullptr);
	if (data == nullptr) {
		cerr << "elf_getdata\n";
		return false;
	}
	GElf_Shdr glink_mem;
	GElf_Shdr *glink = gelf_getshdr (elf_getscn (e, shdr->sh_link), &glink_mem);
	if (glink == nullptr) {
		cerr << "gelf_getshdr for glink\n";
		return false;
	}
	size_t sh_entsize = gelf_fsize (e, ELF_T_DYN, 1, EV_CURRENT);

	for (size_t cnt = 0; cnt < shdr->sh_size / sh_entsize; ++cnt) {
		GElf_Dyn dynmem;
		GElf_Dyn *dyn = gelf_getdyn (data, cnt, &dynmem);
		if (dyn == nullptr) {
			cerr << "gelf_getdyn\n";
			break;
		}

		switch (dyn->d_tag) {
		case DT_NEEDED:
			unresolved.push_back(elf_strptr (e, shdr->sh_link, dyn->d_un.d_val));
			break;
		case DT_RPATH:
			rpath.push_back(elf_strptr (e, shdr->sh_link, dyn->d_un.d_val));
			break;
		}
	}
	return true;
}

static void process_file(string& file, set<string>& s,
	       	vector<string>& orig_rpath,
	       	string& prefix, bool recurse)
{
	bool failed = false;
	Elf *e;
	int fd;
	Elf_Scn *scn = nullptr;
	vector<string> unresolved, resolved, rpaths;

	if ((fd = open(file.c_str(), O_RDONLY, 0)) == -1) {
		cerr << "fd open\n";
		return false;
	}
	e = elf_begin(fd, ELF_C_READ, nullptr);
	if (elf_kind (e) != ELF_K_ELF) {
		cerr << "wrong elf kind\n";
		failed = true;
		goto err1;
	}

	// insert all of original rpath
	for (size_t i = 0; i < orig_rpath.size(); i++) {
		rpaths.push_back(orig_rpath[i]);
	}

	// prep, scan
	while ((scn = elf_nextscn (e, scn)) != nullptr) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_mem);
		if (shdr == nullptr) {
			cerr << "gelf_getshdr for dyn\n";
			failed = true;
			goto err1;
		}

		if (shdr->sh_type == SHT_DYNAMIC) {
			if (!handle_dynamic(e, scn, shdr, unresolved, rpaths)) {
				failed |= true;
			}
		}
	}

	// now resolve it
	for (size_t i = 0; i < unresolved.size(); i++) {
		auto sym = resolve_symbol(unresolved[i], rpaths, prefix);
		resolved.push_back(sym);
	}

	// then push everything into the set
	for (size_t i = 0; i < resolved.size(); i++) {
		s.insert(resolved[i]);
	}

	// recurse
	if (recurse) {
		for (size_t i = 0; i < resolved.size(); i++) {
			if (resolved[i][0] != '/') {
				continue;
			}
			process_file(resolved[i], s, orig_rpath, prefix, true);
		}
	}

err1:
	elf_end(e);
	close(fd);
	return !failed;
}

int main (int argc, char **argv)
{
	vector<string> orig_rpath;
	string prefix = "";
	bool recurse = true;

	int failed = 0, done = 0;

	// args
	int ch;
	while ((ch = getopt(argc, argv, "R:P:n")) != -1) {
		switch (ch) {
		case 'R':
			orig_rpath.push_back(optarg);
			break;
		case 'P':
			prefix = optarg;
			break;
		case 'n':
			recurse = false;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (optind == argc) {
		usage(argv[0]);
		return 1;
	}

	elf_version (EV_CURRENT);
	for (int i = optind; i < argc; i++) {
		done++;
		set<string> deps;
		string name(argv[i]);
		cout << name << ":\n";
		if (!process_file(name, deps, orig_rpath, prefix, recurse)) {
			// failure isn't fatal, but it means we had an issue
			failed++;
		}
		for (auto iter = deps.begin(); iter != deps.end(); ++iter) {
			cout << "\t" << *iter << "\n";
		}
	}
	// if all failed vs. none
	if (failed == done) {
		return 3;
	} else if (failed) { 
		return 2;
	}
	return 0;
}
