# Matrix Synapse Dev Wizard

Fast setup wizard for a Matrix Synapse test environment — a set of scripts that prepares a VPS, 
configures a Synapse server, and wires it with tools for developing bots, plugins, and web clients. 

## Quick Start: Running the Pipeline

### Stage 1 – Set up the switch server

Run the setup script for the switch server.  
At the end of the script execution, API tokens will be printed to the console — **copy and save them**, they will be needed for the following stages.

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-01/01_setup_switch_server.sh')"
```

### Stage 2 – Setup build and deploy the Synapse server

#### 2.1 – Prepare the Synapse server

Prepare the VPS environment for Synapse: install dependencies and base configuration so the host is ready for later deployment (no Synapse build at this step). At the end of the script execution, API tokens will be printed to the console — **copy and save them**, they will be needed for the following stages.

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-02/01_setup_synapse_server.sh')"
```

#### 2.2 – Build the Synapse package

Build a Synapse package with the configuration required for the test environment.

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-02/02_build_synapse_package.sh')"
```

#### 2.3 – Deploy the Synapse package

Deploy the built Synapse package to the server using the previously generated API tokens.

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-02/03_deploy_synapse_package.sh')"
```

### Stage 3 – Frontend and domain setup

#### 3.1 – Set up the frontend server

Prepare the frontend server (web server, runtime, static hosting).

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-03/01_setup_frontend_server.sh')"
```

#### 3.2 – Point your domain to the VPS

At this step you need to connect your domain name to this VPS.  
Log in to your domain registrar or DNS provider and create an **A record** that points your domain (for example, `example.com`) to the public IP address of your VPS or server.

If you already have a Njalla account and an API token, you can use this tool:

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/charon/refs/heads/main/njalla.sh')"
```

#### 3.3 – Build the frontend package

Build the frontend application bundle.

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-03/02_build_frontend_package.sh')"
```

#### 3.4 – Deploy the frontend package

Deploy the built frontend bundle and reload the web server.

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/matrix-synapse-dev-wizard/refs/heads/main/stage-03/03_deploy_frontend_package.sh')"
```


## Donate

If this project is useful to you, consider supporting its development:

XMR: `49nS2i9pTLVYbqv5tUaCGCNSeHQLQkB92QbhbArm14CE77EBf4ewBmPhwuPRfZcJ6GW91Exa399uyLMQXCHZ8S4VNWYmjoN`

Donations are optional but highly appreciated.

## License

This project is licensed under the
[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).
