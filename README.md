# CRM Server

A Node.js REST API backend for a Customer Relationship Management application. Built with Express 5, MongoDB, and JWT authentication.

**Version:** 3.0

---

## Live Links

| | URL |
|---|---|
| Backend | [crm-nodejs-v3.onrender.com](https://crm-nodejs-v3.onrender.com) |
| Frontend | [crm-app-prasanth.netlify.app](https://crm-app-prasanth.netlify.app) |
| Frontend Repo | [github.com/prasanthprabakaran/crm-front](https://github.com/prasanthprabakaran/crm-front) |

---

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express 5
- **Database:** MongoDB (Mongoose)
- **Auth:** JSON Web Tokens (JWT)
- **Environment:** dotenv

---

## Getting Started

### Prerequisites

- Node.js v18+
- MongoDB (local or Atlas)

### Installation

```bash
git clone https://github.com/prasanthprabakaran/crm-server
cd crm-server
npm install
```

### Environment Variables

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `PORT` | Port the server runs on (e.g. `5000`) |
| `MONGO_URI` | MongoDB connection string |
| `JWT_SECRET` | Secret key for signing JWT tokens |
| `CLIENT_URL` | Frontend URL (for CORS) |

### Run Locally

```bash
# Development (with nodemon)
npm run dev

# Production
npm start
```

---

## Folder Structure

```
crm-server/
├── index.js              # App entry point
├── routes/
│   └── rootRouter.js     # Root route aggregator
├── .env.example          # Environment variable template
├── package.json
└── README.md
```

---

## API Endpoints

All routes are prefixed with `/api`.

### Auth

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| POST | `/api/auth/register` | Register a new user | No |
| POST | `/api/auth/login` | Login and receive JWT | No |

### Users

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| GET | `/api/users` | Get all users | Yes |
| GET | `/api/users/:id` | Get a single user | Yes |
| PUT | `/api/users/:id` | Update a user | Yes |
| DELETE | `/api/users/:id` | Delete a user | Yes |

### Tasks

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| GET | `/api/tasks` | Get all tasks | Yes |
| GET | `/api/tasks/:id` | Get a single task | Yes |
| POST | `/api/tasks` | Create a task | Yes |
| PUT | `/api/tasks/:id` | Update a task | Yes |
| DELETE | `/api/tasks/:id` | Delete a task | Yes |

> Protected routes require an `Authorization: Bearer <token>` header.

---

## Deployment

This server is deployed on **Render** (free tier).

### Steps to deploy your own instance

1. Push your repo to GitHub.
2. Go to [render.com](https://render.com) and create a new **Web Service**.
3. Connect your GitHub repo.
4. Set the following:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
5. Add your environment variables under the **Environment** tab (same as `.env`).
6. Deploy — Render will auto-deploy on every push to `main`.

> **Note:** Free tier instances on Render spin down after inactivity. The first request after a cold start may take 30–60 seconds.

---

## License

MIT

---

## Docker

Run the full stack locally with Docker Compose (app + MongoDB):

```bash
docker-compose up --build
```

Stop and remove containers:

```bash
docker-compose down
```

The app will be available at `http://localhost:3002`.

> MongoDB data is persisted in a named volume `mongo_data` so data survives container restarts.

---

## Kubernetes

Manifests are in the `k8s/` folder. Tested locally with Docker Desktop Kubernetes.

### Deploy

```bash
# Build the image first
docker build -t crm-app:latest .

# Apply manifests in order
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

### Verify

```bash
kubectl get all
```

### Tear down

```bash
kubectl delete -f k8s/
```

### What each manifest does

| File | Purpose |
|---|---|
| `configmap.yaml` | Non-sensitive environment variables (PORT, ORIGIN) |
| `secret.yaml` | Sensitive values (MongoDB URL, JWT secrets) — not committed to git |
| `deployment.yaml` | Runs 2 replicas with liveness and readiness probes |
| `service.yaml` | Internal ClusterIP load balancer across pods |
| `ingress.yaml` | External traffic routing via nginx ingress controller |

> `k8s/secret.yaml` is in `.gitignore` — never commit real secrets to version control.

---

## CI/CD

This project uses GitHub Actions for continuous integration. On every push or pull request to `main`/`master`, the pipeline automatically:

- Installs dependencies
- Runs all 28 integration tests against a real MongoDB Atlas test database

A green checkmark on the repo means all tests passed.

To view the workflow: `.github/workflows/ci.yml`