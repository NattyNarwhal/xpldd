/*
 * xpldd: cross-platform ELF ldd
 *
 * Copyright (C) 2020 Calvin Buckley; licensed under the GPLv3
 */
#include <filesystem>
#include <iostream>
#include <map>
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

class Binary {
public:
	string _name;
	vector<string> _depends;
	vector<string> _rpath;
	//string _interp;
	bool _resolved;
};

class XplddState {
	// who needs getters and setters?
public:
	// defaults
	XplddState() {
		_prefix = "";
		_recurse = true;
		_recurse = true;
		_tree = false;

		_done = _failed = 0;
	}

	// configuration passed on args
	string _prefix;
	vector<string> _orig_rpath;
	bool _recurse, _tree;
	// stuff we track
	map<string, Binary*> _found_binaries;
	int _done, _failed;
};

static void usage(string argv0)
{
	cerr << "usage: " << argv0 << " [-nt] [-P path_prefix] [-R rpath_entry..] [elf..]\n";
	cerr << "\t-n: no recursion (optional)\n";
	cerr << "\t-t: show dependencies in a tree (optional)\n";
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
		Binary* binary)
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
			binary->_depends.push_back(elf_strptr (e, shdr->sh_link, dyn->d_un.d_val));
			break;
		case DT_RPATH:
			binary->_rpath.push_back(elf_strptr (e, shdr->sh_link, dyn->d_un.d_val));
			break;
		}
	}
	return true;
}

static bool process_file(string& file, XplddState& state)
{
	bool failed = false;
	Elf *e;
	int fd;
	Elf_Scn *scn = nullptr;

	vector<string> combined_rpath;

	Binary *binary = new Binary();
	binary->_name = file;

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
			if (!handle_dynamic(e, scn, shdr, binary)) {
				failed |= true;
			}
		}
	}

	state._found_binaries[file] = binary;

	// insert all of original rpath plus Binary's (not ideal)
	for (size_t i = 0; i < state._orig_rpath.size(); i++) {
		combined_rpath.push_back(state._orig_rpath[i]);
	}
	for (size_t i = 0; i < binary->_rpath.size(); i++) {
		combined_rpath.push_back(binary->_rpath[i]);
	}

	// now resolve it, and recurse as needed
	for (size_t i = 0; i < binary->_depends.size(); i++) {
		auto sym = resolve_symbol(binary->_depends[i], combined_rpath, state._prefix);
		binary->_depends[i] = sym;
		if (state._recurse) {
			if (binary->_depends[i][0] != '/') {
				// we want an absolute path, not an unresolved one
				continue;
			}
			if (state._found_binaries.count(binary->_depends[i])) {
				// no need to reprocess a binary we already have
				continue;
			}
			process_file(binary->_depends[i], state);
		} else {
			// the binaries won't get added into the list
			// unless we go into process_file, but since we're
			// skipping that, add a skeleton
			Binary* child = new Binary();
			child->_name = binary->_depends[i];
			state._found_binaries[binary->_depends[i]] = child;
		}
	}

err1:
	elf_end(e);
	close(fd);
	return !failed;
}

static void gather_flat_deps(set<string>& all_deps, Binary* binary, XplddState& state)
{
	for (auto iter = binary->_depends.begin(); iter != binary->_depends.end(); ++iter) {
		all_deps.insert(*iter);
		Binary* next = state._found_binaries[*iter];
		if (next != nullptr) {
			gather_flat_deps(all_deps, next, state);
		}
	}
}

static void print_flat_deps(Binary* binary, XplddState& state)
{
	set<string> all_deps;
	gather_flat_deps(all_deps, binary, state);
	for (auto iter = all_deps.begin(); iter != all_deps.end(); ++iter) {
		cout << "\t" << *iter << "\n";
	}
}

static void print_tree_deps(Binary* binary, XplddState& state, int depth)
{
	if (depth > 0) {
		for (int i = 0; i < depth; i++) {
			cout << "\t";
		}
		cout << binary->_name << "\n";
	}
	for (auto iter = binary->_depends.begin(); iter != binary->_depends.end(); ++iter) {
		Binary* next = state._found_binaries[*iter];
		if (next != nullptr) {
			print_tree_deps(next, state, depth + 1);
		}
	}
}

int main (int argc, char **argv)
{
	XplddState state;

	// args
	int ch;
	while ((ch = getopt(argc, argv, "R:P:nt")) != -1) {
		switch (ch) {
		case 'R':
			state._orig_rpath.push_back(optarg);
			break;
		case 'P':
			state._prefix = optarg;
			break;
		case 'n':
			state._recurse = false;
			break;
		case 't':
			state._tree = true;
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
		state._done++;
		string name(argv[i]);
		cout << name << ":\n";
		if (!process_file(name, state)) {
			// failure isn't fatal, but it means we had an issue
			state._failed++;
		}
		Binary* binary = state._found_binaries[name];
		if (binary == nullptr) {
			cerr << "binary couldn't be resolved\n";
			continue;
		}
		if (state._tree) {
			print_tree_deps(binary, state, 0);
		} else {
			print_flat_deps(binary, state);
		}
	}

	// cleanup
	for (auto iter = state._found_binaries.begin(); iter != state._found_binaries.end(); ++iter) {
		delete iter->second;
	}

	// if all failed vs. none
	if (state._failed == state._done) {
		return 3;
	} else if (state._failed) {
		return 2;
	}
	return 0;
}
