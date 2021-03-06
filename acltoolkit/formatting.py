def pretty_print(d, indent=0, padding=20):
    if isinstance(d, dict):
        for key, value in d.items():
            if isinstance(value, str) or isinstance(value, int):
                print(("  " * indent + str(key)).ljust(padding, " ") + ": %s" % value)
            elif isinstance(value, dict):
                print()
                print("  " * indent + str(key))
                pretty_print(value, indent=indent + 1)
            elif isinstance(value, list):
                if all(isinstance(item,str) for item in value):
                    print(("  " * indent + str(key)).ljust(padding, " ") + ": %s" % ", ".join(value))
                elif len(value) > 0 and isinstance(value[0], dict):
                    print()
                    print("  " * indent + str(key))
                    for v in value:
                        pretty_print(v, indent=indent + 1)
                        print()
                else:
                    print(
                        ("  " * indent + str(key)).ljust(padding, " ")
                        + ": %s"
                        % (
                            ("\n" + " " * padding + "  ").join(
                                map(lambda x: str(x), value)
                            )
                        )
                    )
            elif isinstance(value, tuple):
                print("  " * indent + str(key))
                for v in value:
                    pretty_print(v, indent=indent + 1)
            else:
                # Shouldn't end up here
                raise NotImplementedError("Not implemented: %s" % type(value))
    else:
        # Shouldn't end up here
        raise NotImplementedError("Not implemented: %s" % type(d))