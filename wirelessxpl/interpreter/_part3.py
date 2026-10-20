        # Handle flags
        if "--list" in args_list:
            print_info(format_compact_list())
            return

        if "--category" in args_list:
            idx = args_list.index("--category")
            cat = args_list[idx + 1] if idx + 1 < len(args_list) else ""
            print_info(format_compact_list(filter_category=cat))
            return

        if "--help" in args_list or args_list[0] == "help":
            print_info(glossary_help())
            return

        # Search for each provided term
        for query in args_list:
            if query.startswith("--"):
                continue
            results = search_term(query)
            if not results:
                print_info(f"  Term '\033[93m{query}\033[0m' not found. "
                           f"Try: glossary --list")
            else:
                for key, entry in results[:3]:  # max 3 results per query
                    print_info(format_entry(key, entry))

    def command_exec(self, *args, **kwargs):
        os.system(args[0])

    def command_search(self, *args, **kwargs):
        mod_type = ''
        mod_device = ''
        mod_vendor = ''
        existing_modules = [name for _, name, _ in pkgutil.iter_modules([MODULES_DIR])]
        self._build_module_device_index()
        devices = sorted(self._search_devices_cache)

        try:
            keyword = args[0].strip("'\"").lower()
        except IndexError:
            keyword = ''

        if not (len(keyword) or len(kwargs.keys())):
            print_error("Please specify at least search keyword. e.g. 'search wifi'")
            print_error("You can specify options. e.g. 'search type=generic device=wifi vendor=generic wpa3'")
            return

        for (key, value) in kwargs.items():
            if key == 'type':
                if value not in existing_modules:
                    print_error("Unknown module type.")
                    return
                mod_type = f"{value}."
            elif key == 'device':
                normalized_device = self._normalize_device_name(value)
                if normalized_device not in devices:
                    print_error("Unknown device type.")
                    return
                mod_device = normalized_device
            elif key == 'vendor':
                # print_info(' - Vendor:\t{}'.format(value))
                mod_vendor = f".{value}."

        for module in self.modules:
            if mod_type not in str(module):
                continue
            if mod_device:
                module_devices = self._module_device_index.get(module, set())
                if mod_device not in module_devices:
                    continue
            if mod_vendor not in str(module):
                continue
            if not all(word in str(module) for word in keyword.split()):
                continue

            found = humanize_path(module)

            if len(keyword):
                for word in keyword.split():
                    found = found.replace(word, f"\033[31m{word}\033[0m")

            print_info(found)

    @stop_after(2)
    def complete_search(self, text, *args, **kwargs):
        if text:
            return [command for command in self.search_sub_commands if command.startswith(text)]
        else:
            return self.search_sub_commands

    def command_exit(self, *args, **kwargs):
        raise EOFError

