local volumes() = [
    # Use this to cache installed Python code between steps
    {
        "name": "python_install",
        "path": "/usr/local/"
    }
];

# Pipeline template
local test_with(version, do_deploy=false) = {
    kind: "pipeline",
    type: "docker",
    name: "py" + version,
    steps:
        # std.prune removes skipped pipeline stages, since they evaluate to a null element
        std.prune([
            {
                name: "install",
                image: "python:" + version + "-bullseye",
                commands: [
                    "pip install -r requirements.txt",
                    "python setup.py install"
                ],
                volumes: volumes()
            },
            {
                name: "test",
                image: "python:" + version + "-bullseye",
                commands: [
                    "apt-get update",
                    "apt-get install -yy imagemagick gcc-mingw-w64 make",
                    "cd tests && make",
                    "python -m unittest discover . --verbose"
                ],
                volumes: volumes()
            },

            if do_deploy then {
                name: "pypi_upload",
                image: "plugins/pypi",
                settings: {
                    username: "__token__",
                    password: {
                        "from_secret": "pypi_token"
                    }
                },
                when: {
                    event: ["tag"],
                }
            }
        ]),
    volumes: [
        {
            name: "python_install",
            temp: {}
        },
    ],
};

[
    test_with("3.8"),
    test_with("3.9"),
    test_with("3.10"),
    test_with("3.11"),
    test_with("3.12", do_deploy=true),
]
