# =============================================================================
# FASE 9: DEPLOYMENT E PRODUZIONE - CONTAINERIZZAZIONE COMPLETA
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

# =============================================================================
# 1. DOCKERFILE PRINCIPALE
# File: Dockerfile
# =============================================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="Academic Credentials Team"
LABEL version="1.0.0"
LABEL description="Sistema Credenziali Accademiche Decentralizzate"

# Variabili ambiente
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH="/app"

# Directory di lavoro
WORKDIR /app

# Dipendenze di sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    nginx \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Copia requirements
COPY requirements.txt .

# Installa dipendenze Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia codice sorgente
COPY src/ ./src/
COPY web/ ./web/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Copia configurazioni
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Crea directories necessarie
RUN mkdir -p /app/logs /app/data /app/certificates /app/blockchain/artifacts

# Permessi
RUN chown -R www-data:www-data /app && \
    chmod +x /app/scripts/*.sh

# Porta esposta
EXPOSE 80 443 8000 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Comando di avvio
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

# =============================================================================
# 2. DOCKER COMPOSE - STACK COMPLETO
# File: docker-compose.yml
# =============================================================================

version: '3.8'

services:
  # Applicazione principale
  academic-credentials:
    build: .
    container_name: academic-credentials-app
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8000:8000"
      - "8443:8443"
    environment:
      - ENV=production
      - DEBUG=false
      - SECRET_KEY=${SECRET_KEY:-academic_credentials_secret_key}
      - DATABASE_URL=postgresql://user:password@postgres:5432/academic_credentials
      - REDIS_URL=redis://redis:6379/0
      - BLOCKCHAIN_RPC_URL=http://ganache:8545
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./certificates:/app/certificates
      - ./blockchain/artifacts:/app/blockchain/artifacts
    depends_on:
      - postgres
      - redis
      - ganache
    networks:
      - academic-network

  # Database PostgreSQL
  postgres:
    image: postgres:15-alpine
    container_name: academic-credentials-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: academic_credentials
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    networks:
      - academic-network

  # Redis per cache e sessioni
  redis:
    image: redis:7-alpine
    container_name: academic-credentials-cache
    restart: unless-stopped
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - academic-network

  # Ganache per blockchain locale
  ganache:
    image: trufflesuite/ganache-cli:latest
    container_name: academic-credentials-blockchain
    restart: unless-stopped
    command: >
      ganache-cli
      --host 0.0.0.0
      --port 8545
      --networkId 1337
      --accounts 10
      --deterministic
      --mnemonic "academic credentials demo mnemonic seed phrase for development only"
    ports:
      - "8545:8545"
    networks:
      - academic-network

  # Monitoring con Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: academic-credentials-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    ports:
      - "9090:9090"
    volumes:
      - ./docker/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - academic-network

  # Grafana per dashboard monitoring
  grafana:
    image: grafana/grafana:latest
    container_name: academic-credentials-grafana
    restart: unless-stopped
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin123
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./docker/grafana/provisioning:/etc/grafana/provisioning
    networks:
      - academic-network

  # Elasticsearch per logging
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.10.0
    container_name: academic-credentials-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    networks:
      - academic-network

  # Kibana per visualizzazione log
  kibana:
    image: docker.elastic.co/kibana/kibana:8.10.0
    container_name: academic-credentials-kibana
    restart: unless-stopped
    environment:
      ELASTICSEARCH_HOSTS: http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - academic-network

  # IPFS per storage decentralizzato (opzionale)
  ipfs:
    image: ipfs/go-ipfs:latest
    container_name: academic-credentials-ipfs
    restart: unless-stopped
    ports:
      - "4001:4001"
      - "5001:5001"
      - "8080:8080"
    volumes:
      - ipfs_data:/data/ipfs
    networks:
      - academic-network

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
  elasticsearch_data:
  ipfs_data:

networks:
  academic-network:
    driver: bridge

# =============================================================================
# 3. CONFIGURAZIONE NGINX
# File: docker/nginx.conf
# =============================================================================

user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /app/logs/nginx-access.log main;
    error_log /app/logs/nginx-error.log warn;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 50M;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;

    # Upstream backend
    upstream academic_backend {
        server 127.0.0.1:8000;
        keepalive 32;
    }

    # HTTP server (redirect to HTTPS)
    server {
        listen 80;
        server_name _;
        
        location /.well-known/acme-challenge/ {
            root /var/www/certbot;
        }
        
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS server
    server {
        listen 443 ssl http2;
        server_name academic-credentials.local;

        # SSL configuration
        ssl_certificate /app/certificates/server.crt;
        ssl_certificate_key /app/certificates/server.key;
        
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;

        # Security
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # Static files
        location /static/ {
            alias /app/web/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # API endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://academic_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Authentication endpoints
        location ~ ^/(login|logout) {
            limit_req zone=auth burst=10 nodelay;
            
            proxy_pass http://academic_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Main application
        location / {
            proxy_pass http://academic_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        # Health check
        location /health {
            access_log off;
            proxy_pass http://academic_backend;
        }
    }
}

# =============================================================================
# 4. SUPERVISORD CONFIGURATION
# File: docker/supervisord.conf
# =============================================================================

[supervisord]
nodaemon=true
logfile=/app/logs/supervisord.log
pidfile=/app/logs/supervisord.pid
user=root

[program:nginx]
command=/usr/sbin/nginx -g "daemon off;"
autostart=true
autorestart=true
stderr_logfile=/app/logs/nginx-stderr.log
stdout_logfile=/app/logs/nginx-stdout.log

[program:academic-app]
command=python -m uvicorn web.dashboard:app --host 0.0.0.0 --port 8000 --workers 4
directory=/app
autostart=true
autorestart=true
stderr_logfile=/app/logs/app-stderr.log
stdout_logfile=/app/logs/app-stdout.log
environment=PYTHONPATH="/app"

[program:secure-api]
command=python src/communication/secure_server.py
directory=/app
autostart=true
autorestart=true
stderr_logfile=/app/logs/secure-api-stderr.log
stdout_logfile=/app/logs/secure-api-stdout.log
environment=PYTHONPATH="/app"

# =============================================================================
# 5. REQUIREMENTS.TXT
# File: requirements.txt
# =============================================================================

# Core dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
jinja2==3.1.2
python-multipart==0.0.6

# Cryptography
cryptography==41.0.7
pycryptodome==3.19.0

# Blockchain
web3==6.11.3
py-solc-x==1.12.2
eth-account==0.9.0

# Database
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
alembic==1.13.0

# Cache and sessions
redis==5.0.1
python-jose[cryptography]==3.3.0

# HTTP and networking
requests==2.31.0
httpx==0.25.2
websockets==12.0

# Data processing
pandas==2.1.3
numpy==1.24.4
lxml==4.9.3

# Testing
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0

# Monitoring and logging
prometheus-client==0.19.0
structlog==23.2.0
sentry-sdk==1.38.0

# Development
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# =============================================================================
# 6. SCRIPT DEPLOYMENT
# File: scripts/deploy.sh
# =============================================================================

#!/bin/bash

# Academic Credentials Deployment Script
set -e

echo "🚀 Academic Credentials Deployment Script"
echo "=========================================="

# Variabili
ENVIRONMENT=${1:-production}
PROJECT_NAME="academic-credentials"
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"

echo "📋 Environment: $ENVIRONMENT"

# Funzioni
create_directories() {
    echo "📁 Creating directories..."
    mkdir -p data logs certificates blockchain/artifacts backups
    mkdir -p docker/grafana/provisioning/{dashboards,datasources}
}

generate_ssl_certificates() {
    echo "🔐 Generating SSL certificates..."
    if [ ! -f "certificates/server.key" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout certificates/server.key \
            -out certificates/server.crt \
            -subj "/C=IT/ST=Campania/L=Salerno/O=Academic Credentials/CN=localhost"
        echo "✅ SSL certificates generated"
    else
        echo "✅ SSL certificates already exist"
    fi
}

setup_environment() {
    echo "⚙️  Setting up environment..."
    
    # Crea .env se non esiste
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# Academic Credentials Environment
ENV=$ENVIRONMENT
DEBUG=false
SECRET_KEY=$(openssl rand -hex 32)

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/academic_credentials

# Redis
REDIS_URL=redis://localhost:6379/0

# Blockchain
BLOCKCHAIN_RPC_URL=http://localhost:8545
BLOCKCHAIN_NETWORK=ganache_local

# Monitoring
SENTRY_DSN=
PROMETHEUS_ENABLED=true

# Email (optional)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EOF
        echo "✅ Environment file created"
    fi
}

deploy_infrastructure() {
    echo "🏗️  Deploying infrastructure..."
    
    # Docker Compose
    if [ "$ENVIRONMENT" = "production" ]; then
        docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    else
        docker-compose up -d
    fi
    
    echo "✅ Infrastructure deployed"
}

wait_for_services() {
    echo "⏳ Waiting for services to be ready..."
    
    # Wait for PostgreSQL
    until docker-compose exec postgres pg_isready -U user -d academic_credentials; do
        echo "Waiting for PostgreSQL..."
        sleep 2
    done
    
    # Wait for Redis
    until docker-compose exec redis redis-cli ping; do
        echo "Waiting for Redis..."
        sleep 2
    done
    
    # Wait for Ganache
    until curl -s http://localhost:8545 > /dev/null; do
        echo "Waiting for Ganache..."
        sleep 2
    done
    
    echo "✅ All services ready"
}

run_migrations() {
    echo "🗃️  Running database migrations..."
    docker-compose exec academic-credentials python scripts/migrate.py
    echo "✅ Migrations completed"
}

deploy_smart_contracts() {
    echo "📝 Deploying smart contracts..."
    docker-compose exec academic-credentials python scripts/deploy_contracts.py
    echo "✅ Smart contracts deployed"
}

run_tests() {
    echo "🧪 Running tests..."
    docker-compose exec academic-credentials python -m pytest tests/ -v
    echo "✅ Tests completed"
}

setup_monitoring() {
    echo "📊 Setting up monitoring..."
    
    # Grafana datasources
    cat > docker/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF
    
    echo "✅ Monitoring configured"
}

backup_data() {
    if [ "$ENVIRONMENT" = "production" ]; then
        echo "💾 Creating backup..."
        mkdir -p $BACKUP_DIR
        
        # Database backup
        docker-compose exec postgres pg_dump -U user academic_credentials > $BACKUP_DIR/database.sql
        
        # Data backup
        cp -r data $BACKUP_DIR/
        cp -r certificates $BACKUP_DIR/
        
        echo "✅ Backup created: $BACKUP_DIR"
    fi
}

show_status() {
    echo ""
    echo "📊 DEPLOYMENT STATUS"
    echo "===================="
    
    # Services status
    docker-compose ps
    
    echo ""
    echo "🌐 ENDPOINTS"
    echo "============"
    echo "Dashboard:    https://localhost"
    echo "API:          https://localhost/api"
    echo "Prometheus:   http://localhost:9090"
    echo "Grafana:      http://localhost:3000 (admin/admin123)"
    echo "Kibana:       http://localhost:5601"
    echo "Ganache:      http://localhost:8545"
    
    echo ""
    echo "🔑 DEFAULT CREDENTIALS"
    echo "======================"
    echo "Dashboard:    admin / demo123"
    echo "Grafana:      admin / admin123"
    echo "PostgreSQL:   user / password"
}

# Funzione di rollback
rollback() {
    echo "🔄 Rolling back deployment..."
    docker-compose down
    
    if [ -d "$BACKUP_DIR" ]; then
        echo "📥 Restoring from backup: $BACKUP_DIR"
        cp -r $BACKUP_DIR/data .
        cp -r $BACKUP_DIR/certificates .
        # Restore database se necessario
    fi
    
    echo "✅ Rollback completed"
}

# Trap per cleanup su errore
trap 'echo "❌ Deployment failed! Check logs."; rollback; exit 1' ERR

# Main deployment flow
main() {
    echo "Starting deployment..."
    
    create_directories
    generate_ssl_certificates
    setup_environment
    setup_monitoring
    
    if [ "$ENVIRONMENT" = "production" ]; then
        backup_data
    fi
    
    deploy_infrastructure
    wait_for_services
    run_migrations
    deploy_smart_contracts
    
    if [ "$ENVIRONMENT" != "production" ]; then
        run_tests
    fi
    
    show_status
    
    echo ""
    echo "🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!"
    echo "======================================"
}

# Gestione argomenti
case "${2:-deploy}" in
    "deploy")
        main
        ;;
    "rollback")
        rollback
        ;;
    "status")
        show_status
        ;;
    "backup")
        backup_data
        ;;
    *)
        echo "Usage: $0 [environment] [deploy|rollback|status|backup]"
        echo "Example: $0 production deploy"
        exit 1
        ;;
esac

# =============================================================================
# 7. CONFIGURAZIONE PROMETHEUS
# File: docker/prometheus.yml
# =============================================================================

global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'academic-credentials'
    static_configs:
      - targets: ['academic-credentials:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']

  - job_name: 'nginx'
    static_configs:
      - targets: ['academic-credentials:80']

# =============================================================================
# 8. INIT SQL
# File: docker/init.sql
# =============================================================================

-- Academic Credentials Database Initialization

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    university_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Universities table
CREATE TABLE IF NOT EXISTS universities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    country VARCHAR(2) NOT NULL,
    erasmus_code VARCHAR(20),
    website VARCHAR(255),
    blockchain_address VARCHAR(42),
    certificate_thumbprint VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credential_id VARCHAR(255) UNIQUE NOT NULL,
    issuer_id UUID REFERENCES universities(id),
    student_id VARCHAR(255) NOT NULL,
    credential_data JSONB NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    blockchain_tx_hash VARCHAR(66),
    status VARCHAR(20) DEFAULT 'active',
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revocation_reason TEXT
);

-- Verifications table
CREATE TABLE IF NOT EXISTS verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    presentation_id VARCHAR(255) NOT NULL,
    verifier_id UUID REFERENCES universities(id),
    verification_result JSONB NOT NULL,
    confidence_score DECIMAL(3,2),
    verified_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verification_level VARCHAR(20) NOT NULL,
    purpose TEXT
);

-- Credit recognitions table
CREATE TABLE IF NOT EXISTS credit_recognitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(255) UNIQUE NOT NULL,
    student_id VARCHAR(255) NOT NULL,
    presentation_id VARCHAR(255) NOT NULL,
    university_id UUID REFERENCES universities(id),
    total_credits_requested INTEGER DEFAULT 0,
    total_credits_recognized INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'pending',
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    reviewed_by UUID REFERENCES users(id),
    decision_notes TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_credentials_student_id ON credentials(student_id);
CREATE INDEX IF NOT EXISTS idx_credentials_issuer_id ON credentials(issuer_id);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
CREATE INDEX IF NOT EXISTS idx_verifications_verifier_id ON verifications(verifier_id);
CREATE INDEX IF NOT EXISTS idx_credit_recognitions_student_id ON credit_recognitions(student_id);
CREATE INDEX IF NOT EXISTS idx_credit_recognitions_status ON credit_recognitions(status);

-- Sample data
INSERT INTO universities (name, country, erasmus_code) VALUES
('Università degli Studi di Salerno', 'IT', 'I SALERNO01'),
('Université de Rennes', 'FR', 'F RENNES01'),
('Technical University of Munich', 'DE', 'D MUNCHEN02')
ON CONFLICT DO NOTHING;

INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@academic-credentials.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNieLceTYn', 'admin'),
('issuer', 'issuer@academic-credentials.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNieLceTYn', 'issuer'),
('verifier', 'verifier@academic-credentials.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNieLceTYn', 'verifier')
ON CONFLICT DO NOTHING;

# =============================================================================
# 9. MAKEFILE PER AUTOMAZIONE
# File: Makefile
# =============================================================================

.PHONY: help build start stop restart logs clean test deploy backup

# Default target
help:
	@echo "Academic Credentials - Available commands:"
	@echo ""
	@echo "  build     - Build Docker images"
	@echo "  start     - Start all services"
	@echo "  stop      - Stop all services"
	@echo "  restart   - Restart all services"
	@echo "  logs      - Show logs"
	@echo "  clean     - Clean up containers and volumes"
	@echo "  test      - Run tests"
	@echo "  deploy    - Deploy to production"
	@echo "  backup    - Create backup"
	@echo "  status    - Show services status"

build:
	@echo "🔨 Building Docker images..."
	docker-compose build

start:
	@echo "🚀 Starting services..."
	docker-compose up -d
	@echo "✅ Services started. Dashboard: https://localhost"

stop:
	@echo "🛑 Stopping services..."
	docker-compose down

restart: stop start

logs:
	@echo "📋 Showing logs..."
	docker-compose logs -f

clean:
	@echo "🧹 Cleaning up..."
	docker-compose down -v --remove-orphans
	docker system prune -f

test:
	@echo "🧪 Running tests..."
	docker-compose exec academic-credentials python -m pytest tests/ -v

deploy:
	@echo "🚀 Deploying to production..."
	./scripts/deploy.sh production deploy

backup:
	@echo "💾 Creating backup..."
	./scripts/deploy.sh production backup

status:
	@echo "📊 Services status:"
	docker-compose ps

# Development targets
dev-setup:
	@echo "🔧 Setting up development environment..."
	pip install -r requirements.txt
	python scripts/setup_dev.py

dev-start:
	@echo "🔬 Starting development server..."
	python web/dashboard.py

# Testing targets
test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-e2e:
	python testing/end_to_end_testing.py

# Database targets
db-migrate:
	docker-compose exec academic-credentials python scripts/migrate.py

db-reset:
	docker-compose exec postgres psql -U user -d academic_credentials -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	docker-compose exec academic-credentials python scripts/migrate.py

# Security targets
security-scan:
	@echo "🔐 Running security scan..."
	docker run --rm -v $(PWD):/src securecodewarrior/docker-image-validator /src

# Performance targets
performance-test:
	@echo "⚡ Running performance tests..."
	docker run --rm -v $(PWD):/src --network host loadimpact/k6 run /src/tests/performance/load_test.js