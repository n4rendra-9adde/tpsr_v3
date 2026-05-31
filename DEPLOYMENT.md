# TPSR Deployment Runbook

## Overview
The Tamper-Proof SBOM Registry (TPSR) operates on a split-deployment hybrid model. The backend infrastructure (Hyperledger Fabric, PostgreSQL, Node.js API) runs locally and is exposed via an Ngrok tunnel. The React dashboard frontend is built as a static site and hosted publicly on GitHub Pages.

## Deployment Order
1. Generate certificates & start Fabric network
2. Start PostgreSQL & apply database migrations
3. Start backend Node.js API
4. Establish Ngrok public tunnel
5. Configure React dashboard environment variables
6. Deploy React dashboard to GitHub Pages

## Prerequisites
- Docker & Docker Compose
- Node.js (v16+) & npm
- Go toolchain (v1.20+)
- Ngrok account (for static domain tunneling)
- Git (configured for pushing to GitHub)

## Step-by-Step Deployment

### 1. Start Hyperledger Fabric
Navigate to the `network/scripts/` directory and execute the initialization scripts. These will generate the cryptographic materials, boot the Docker containers, create the channel, and deploy the Go chaincode.
```bash
./network/scripts/generate-crypto.sh
./network/scripts/start-network.sh
./network/scripts/create-channel.sh
./network/scripts/deploy-chaincode.sh
```

### 2. Start PostgreSQL & Apply Migrations
The PostgreSQL database runs as a Docker container (`tpsr-postgres`). Ensure the container is running, then apply the schema migrations in exact order:
```bash
# Assuming the container is named tpsr-postgres
docker exec -i tpsr-postgres psql -U tpsr -d tpsr < db/migrations/001_init_postgresql.sql
docker exec -i tpsr-postgres psql -U tpsr -d tpsr < db/migrations/002_policy_governance.sql
docker exec -i tpsr-postgres psql -U tpsr -d tpsr < db/migrations/003_tamper_intelligence.sql
docker exec -i tpsr-postgres psql -U tpsr -d tpsr < db/migrations/004_lifecycle_governance.sql
```

### 3. Start Backend API
Navigate to the `api/` directory. Ensure `api/.env` is configured with the correct PostgreSQL credentials and Fabric wallet paths.
```bash
cd api
npm install
npm start
```
*The API will start on `http://localhost:3000`.*

### 4. Establish Ngrok Tunnel
To allow the GitHub Pages dashboard to communicate with the local API, establish an Ngrok tunnel. If you have a static Ngrok domain, use it here:
```bash
ngrok http 3000
```
*Take note of the generated HTTPS URL (e.g., `https://poster-lankiness-payback.ngrok-free.dev`).*

### 5. Configure Dashboard
Navigate to the `dashboard/` directory. Update the `dashboard/.env` file with your active Ngrok URL:
```env
REACT_APP_API_BASE_URL=https://<YOUR-NGROK-URL>/api
```
*Note: The React app is configured to automatically inject the `ngrok-skip-browser-warning` header into all Axios requests to bypass the Ngrok free-tier intercept page.*

### 6. Deploy Dashboard to GitHub Pages
To publish the dashboard publicly, execute the deployment script. Ensure the `homepage` URL in `dashboard/package.json` points to your GitHub Pages domain.
```bash
cd dashboard
npm run deploy
```
*The dashboard will be compiled into an optimized static build and pushed to the `gh-pages` branch.*

## Safe Shutdown Procedures
To safely halt the environment overnight without destroying persistent ledger data or database records:
```bash
# Stop all docker containers gracefully
docker stop $(docker ps -aq)

# Kill the node and ngrok processes
killall node
killall ngrok
```
To resume operations the next day, simply run `docker start $(docker ps -aq)`, restart the API, and start Ngrok.

## Troubleshooting
- **Network Error on Dashboard**: If the dashboard fails to load data, confirm that the Ngrok tunnel is active and the URL matches `dashboard/.env`. If the Ngrok URL changed, you must update the `.env` and run `npm run deploy` again.
- **Database Column Errors**: If the API crashes stating `column X does not exist`, ensure all four SQL migration files were successfully applied to the PostgreSQL container.
- **Fabric Connection Refused**: Verify that the `tpsr-postgres` and Fabric `orderer/peer` containers are actually running via `docker ps`.
