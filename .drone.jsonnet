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
                image: "python:" + version + "-bookworm",
                commands: [
                    "pip install -r requirements.txt",
                    "python setup.py install"
                ],
                volumes: volumes()
            },
            {
                name: "test",
                image: "python:" + version + "-bookworm",
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
            },

            if do_deploy then {
                name: "doc",
                image: "python:" + version + "-bookworm",
                commands: [
                    "pip install pdoc3",
                    "pdoc --html icoextract --template-dir pdoc/templates",
                    "ln html/icoextract/index.html icoextract.html"
                ],
                volumes: volumes(),
            },

            if do_deploy then {
                name: "doc_upload",
                image: "techknowlogick/drone-b2",
                settings: {
                    bucket: "jlu5-ci-doc",
                    account: {from_secret: "b2_account"},
                    key: {from_secret: "b2_key"},
                    source: "icoextract.html",
                    target: "/",
                },
                when: {
                    branch: ["master", "ci-*"],
                    event: ["push"],
                },
            },
        ]),
    volumes: [
        {
            name: "python_install",
            temp: {}
        },
    ],
};

[
    test_with("3.9"),
    test_with("3.12"),
    test_with("3.13", do_deploy=true),
]
