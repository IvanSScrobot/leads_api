# Kubernetes Deployment Guide

This guide explains how to deploy the Ardent Intake API to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (v1.19+)
- `kubectl` configured to access your cluster
- Docker installed for building images
- Nginx Ingress Controller installed in your cluster

## Quick Start

### 1. Build Docker Image

```bash
# Build the Docker image
docker build -t ardent-intake-api:latest .

# Tag for your registry (optional)
docker tag ardent-intake-api:latest your-registry.com/ardent-intake-api:latest

# Push to registry (if using remote registry)
docker push your-registry.com/ardent-intake-api:latest
```

### 2. Update Kubernetes Manifests

#### Update Secret (k8s/secret.yaml)

**IMPORTANT:** Replace the test HMAC secret keys with production values:

```bash
# Generate secure secrets (example)
openssl rand -base64 32

# Update k8s/secret.yaml with your production secrets
```

#### Update Ingress (k8s/ingress.yaml)

Update the host in `k8s/ingress.yaml`:

```yaml
spec:
  rules:
  - host: api.yourdomain.com  # Update this
```

For TLS, uncomment and configure the TLS section:

```yaml
tls:
- hosts:
  - api.yourdomain.com
  secretName: ardent-intake-tls  # Your TLS certificate secret
```

#### Update Deployment Image (k8s/deployment.yaml)

If using a custom registry, update the image reference:

```yaml
spec:
  containers:
  - name: ardent-intake-api
    image: your-registry.com/ardent-intake-api:latest  # Update this
```

### 3. Deploy to Kubernetes

Deploy all manifests in order:

```bash
# Create the namespace (optional)
kubectl create namespace ardent-intake

# Apply the secret (contains HMAC keys)
kubectl apply -f k8s/secret.yaml

# Apply the deployment
kubectl apply -f k8s/deployment.yaml

# Apply the service
kubectl apply -f k8s/service.yaml

# Apply the ingress
kubectl apply -f k8s/ingress.yaml
```

Or apply all at once:

```bash
kubectl apply -f k8s/
```

### 4. Verify Deployment

```bash
# Check if pods are running
kubectl get pods -l app=ardent-intake-api

# Check deployment status
kubectl rollout status deployment/ardent-intake-api

# Check service
kubectl get svc ardent-intake-api

# Check ingress
kubectl get ingress ardent-intake-api

# View logs
kubectl logs -l app=ardent-intake-api --tail=50 -f
```

### 5. Test the Deployment

```bash
# Get the ingress IP/hostname
kubectl get ingress ardent-intake-api

# Test health endpoint
curl http://your-domain.com/health

# Test with proper HMAC authentication
python test_client.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Internet                             │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Kubernetes Ingress (Nginx)                 │
│            Host: api.yourdomain.com                     │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│           Service: ardent-intake-api (ClusterIP)        │
│                  Port: 80 → 8000                        │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│      Deployment: ardent-intake-api (2 replicas)         │
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │  Pod 1           │      │  Pod 2           │        │
│  │  Container:      │      │  Container:      │        │
│  │  - FastAPI App   │      │  - FastAPI App   │        │
│  │  - Port: 8000    │      │  - Port: 8000    │        │
│  │  - HMAC Secrets  │      │  - HMAC Secrets  │        │
│  │    from Secret   │      │    from Secret   │        │
│  └──────────────────┘      └──────────────────┘        │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│         Secret: ardent-intake-hmac-secret               │
│         - HMAC_SECRET_KEY_PK_TEST_123                   │
│         - HMAC_SECRET_KEY_PK_TEST_456                   │
└─────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

The application reads HMAC secrets from environment variables injected by Kubernetes:

- `HMAC_SECRET_KEY_PK_TEST_123`: Secret key for public key `pk_test_123`
- `HMAC_SECRET_KEY_PK_TEST_456`: Secret key for public key `pk_test_456`

These are loaded from the Kubernetes Secret and injected into the pods.

### Resource Limits

Current resource configuration:

**Requests:**
- Memory: 128Mi
- CPU: 100m

**Limits:**
- Memory: 256Mi
- CPU: 500m

Adjust in `k8s/deployment.yaml` based on your load requirements.

### Replicas

Default: 2 replicas for high availability

Adjust in `k8s/deployment.yaml`:

```yaml
spec:
  replicas: 3  # Increase for higher load
```

Or use Horizontal Pod Autoscaler:

```bash
kubectl autoscale deployment ardent-intake-api \
  --cpu-percent=70 \
  --min=2 \
  --max=10
```

## Security Best Practices

### 1. Secrets Management

- **Never commit real secrets to Git**
- Use Kubernetes Secrets or external secret management (e.g., AWS Secrets Manager, HashiCorp Vault)
- Rotate secrets regularly
- Use different secrets for each environment (dev, staging, prod)

### 2. TLS/HTTPS

Configure TLS in the Ingress:

```bash
# Create TLS secret from certificate
kubectl create secret tls ardent-intake-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

Or use cert-manager for automatic certificate management:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Add annotation to ingress
annotations:
  cert-manager.io/cluster-issuer: "letsencrypt-prod"
```

### 3. Network Policies

Restrict pod-to-pod communication:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ardent-intake-api-netpol
spec:
  podSelector:
    matchLabels:
      app: ardent-intake-api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8000
```

### 4. Pod Security

The deployment uses security best practices:

- Runs as non-root user (UID 1000)
- Drops all capabilities
- Disallows privilege escalation

## Monitoring

### Health Checks

The deployment includes:

- **Liveness probe**: Checks if the container is alive
- **Readiness probe**: Checks if the pod is ready to receive traffic

Both use the `/health` endpoint.

### Logs

View application logs:

```bash
# All pods
kubectl logs -l app=ardent-intake-api -f

# Specific pod
kubectl logs <pod-name> -f

# Previous instance (if crashed)
kubectl logs <pod-name> --previous
```

### Metrics

Add Prometheus annotations to scrape metrics:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8000"
    prometheus.io/path: "/metrics"
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl describe pod <pod-name>

# Check events
kubectl get events --sort-by='.lastTimestamp'

# Check logs
kubectl logs <pod-name>
```

### Ingress Not Working

```bash
# Check ingress status
kubectl describe ingress ardent-intake-api

# Check nginx ingress logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx
```

### Authentication Failures

1. Verify secrets are properly mounted:
   ```bash
   kubectl exec <pod-name> -- env | grep HMAC
   ```

2. Check if secrets exist:
   ```bash
   kubectl get secret ardent-intake-hmac-secret
   kubectl describe secret ardent-intake-hmac-secret
   ```

### High Memory Usage

Scale up resources:

```bash
kubectl patch deployment ardent-intake-api -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"ardent-intake-api","resources":{"limits":{"memory":"512Mi"}}}]}}}}'
```

## Updates and Rollouts

### Update Application

```bash
# Build new image with version tag
docker build -t ardent-intake-api:v1.1.0 .
docker push your-registry.com/ardent-intake-api:v1.1.0

# Update deployment
kubectl set image deployment/ardent-intake-api \
  ardent-intake-api=your-registry.com/ardent-intake-api:v1.1.0

# Monitor rollout
kubectl rollout status deployment/ardent-intake-api

# Rollback if needed
kubectl rollout undo deployment/ardent-intake-api
```

### Update Secrets

```bash
# Update secret in k8s/secret.yaml
kubectl apply -f k8s/secret.yaml

# Restart pods to pick up new secrets
kubectl rollout restart deployment/ardent-intake-api
```

## Cleanup

Remove all resources:

```bash
kubectl delete -f k8s/
```

Or individually:

```bash
kubectl delete ingress ardent-intake-api
kubectl delete service ardent-intake-api
kubectl delete deployment ardent-intake-api
kubectl delete secret ardent-intake-hmac-secret
```

## Production Checklist

- [ ] Replace test HMAC secrets with production secrets
- [ ] Configure TLS/HTTPS on Ingress
- [ ] Update Ingress host to production domain
- [ ] Set appropriate resource limits based on load testing
- [ ] Configure Horizontal Pod Autoscaling
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Implement Network Policies
- [ ] Set up backup/disaster recovery
- [ ] Document runbook for operations team
- [ ] Load test the deployment
- [ ] Set up CI/CD pipeline

## Support

For issues or questions, refer to the main [README.md](README.md) for API documentation and testing instructions.