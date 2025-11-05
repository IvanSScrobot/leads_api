# Kubernetes Manifests

This directory contains Kubernetes manifests for deploying the Ardent Intake API.

## Files

- **secret.yaml**: Kubernetes Secret containing HMAC secret keys
- **deployment.yaml**: Deployment with 2 replicas, health checks, and resource limits
- **service.yaml**: ClusterIP Service exposing the deployment
- **ingress.yaml**: Ingress for external access with Nginx annotations

## Quick Deploy

```bash
# Apply all manifests
kubectl apply -f k8s/

# Verify deployment
kubectl get all -l app=ardent-intake-api
```

## Important Notes

⚠️ **Before deploying to production:**

1. Update HMAC secrets in `secret.yaml` with production values
2. Change the Ingress host in `ingress.yaml` to your domain
3. Configure TLS certificates for HTTPS
4. Adjust resource limits based on your requirements

See [DEPLOYMENT.md](../DEPLOYMENT.md) for detailed deployment instructions.