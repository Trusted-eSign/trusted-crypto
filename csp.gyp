{
    "targets": [
        { 
            "target_name": "csp_trusted",
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
                            "-L<(csp_root) -lcapi20"
                        ],

                        "include_dirs": [
                            "/opt/cprocsp/include"
                        ],

                        "defines": [ "CPROCSP" ]
                    }
                ]
            ]
        }
    ]
}