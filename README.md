![CloudPeeker Logo](.github/cloud-peeker.png)

## Overview
CloudPeeker is a tool for quickly scanning a list of domains for the "ownCloud / Nextcloud Unprotected Data Directory" vulnerability. It efficiently checks for this specific vulnerability across multiple domains.

## Quick Start
1. **Building the Docker Image:**
    Use the provided `Dockerfile` to build a Docker image:
    ```
    docker build -t cloudpeeker .
    ```

2. **Running the Tool:**
    Execute CloudPeeker with the following Docker command:
    ```
    docker run --rm cloudpeeker http://vulnerable-nextcloud-for-clouddrain.lednerb.de
    ```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Repository
Find this project on GitHub: [Lednerb/CloudPeeker](https://github.com/Lednerb/CloudPeeker)

## Credits
This scanning tool is part of the IT security study "CloudDrain" conducted by Lednerb IT-Security GmbH. 

The aim of this study is to investigate the impact of the "ownCloud / Nextcloud Unprotected Data Directory" vulnerability. A total of 921,220,480 domains were analyzed. Among these, over 255 million domains from the geographical European countries and over 655 million domains from the .com domain range were scanned.

[» Have a look at the full whitepaper by clicking here «](https://lednerb.de/en/research/CloudDrain?utm_campaign=CloudDrain&utm_source=GitHub)
