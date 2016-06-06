{
    "targets": [
            "conditions": [
                [
                    "OS=='win'",
                    {
                    },
                    {
                        "conditions": [
                            [
                                "target_arch=='x64'",
                                {
                                    "variables": {
                                        "csp_root%": "/opt/cprocsp/lib/amd64"
                                    }
                                },
                                {
                                    "variables": {
                                        "csp_root%": "/opt/cprocsp/lib/ia32"
                                    }
                                }
                            ]
                        ],

                        "libraries": [
                        ],

                        "include_dirs": [
                            "/opt/cprocsp/include"
                        ],
                    }
                ]
            ]
        }
    ]
}
