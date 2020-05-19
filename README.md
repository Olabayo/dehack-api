# Coffee Shop Community Library (CSCL)
## Getting Started
### Requirements:
- Python3
- pip3
- [Docker](https://docs.docker.com/install/)
- [docker-compose](https://docs.docker.com/compose/install/)

### Installation:
`pip3 install -r requirements.txt`  

If using a virtual development environment i.e. `virtualenv`:
```
virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Docker & Docker-Compose
Docker containers are used to facilitate local development.

### Upgrade docker postgres 
https://github.com/Hack-Diversity/cscl_local_db

Use cscl_db.sql in this seed folder to update seed folder in standalone postgres docker, then run `docker-compose down -v` and the `docker-composer up` to update the standalone postgres docker with the new database structure

#### Commands
| Command | Description |
|:---|---|
| `docker-compose up` | Start the local development environment |
| `docker-compose down` | Stop the local development environment.|

Once up and running, you can access your local api by going to http://127.0.0.1:5000.


### Environment Variables
Environment variables allow you to configure your application environment. These values will be passed to the API and can be retrieved by using `os.get_env`.

| Variable | Description |
|---|---|
| FLASK_APP | Name of application that the Flask development server should start. This should be the name of your Python package relative to your current directory. i.e `cscl_api`|
| FLASK_ENV | Environment type that FLask should be running in. `development` enables Debug and should only be used for local development. `production` disables debug and is appropriate for a production build. |
| DATABASE_URL (Host Machine Postgres) | URL to Postgres server. Must start with `postgresql://user:password@host.docker.internal/database` |
| DATABASE_URL (Docker Postgres)| URL to Postgres server. Must start with `postgresql://user:password@postgres/database` |

## API
The API


### Endpoints

#### Swagger documentation
http://localhost:5000/apidocs/
