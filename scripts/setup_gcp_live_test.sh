#!/usr/bin/env bash
#
# setup_gcp_live_test.sh
#
# Sets up the GCP Organization / Folder hierarchy, consolidated policy projects,
# per-runner Service Accounts, and Workload Identity Federation (WIF) for live testing.
#
# Requirements:
#   - gcloud CLI authenticated with Organization Administrator or Folder Administrator role.
#   - Organization ID or parent Folder ID.
#   - Note: No billing account is required (IAM & Policy operations are free).

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration & Inputs
# ------------------------------------------------------------------------------
PARENT_FOLDER_ID="${PARENT_FOLDER_ID:-}"       # e.g., "123456789012" (leave empty if using ORG_ID)
ORGANIZATION_ID="${ORGANIZATION_ID:-}"         # e.g., "123456789012" (leave empty if using PARENT_FOLDER_ID)
PROJECT_PREFIX="${PROJECT_PREFIX:-sakm-ci}"    # Prefix for test projects (max 18 chars recommended)
GITHUB_REPO="${GITHUB_REPO:-jay0lee/go-sa-key-manager}" # Target GitHub repo

# Colors for formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  GCP Live Test Infrastructure Provisioning                     ${NC}"
echo -e "${BLUE}  Target GitHub Repo: ${GITHUB_REPO}                           ${NC}"
echo -e "${BLUE}================================================================${NC}"

# Validate Inputs
if [ -z "${PARENT_FOLDER_ID}" ] && [ -z "${ORGANIZATION_ID}" ]; then
  echo -e "${RED}ERROR: Either PARENT_FOLDER_ID or ORGANIZATION_ID must be provided.${NC}"
  echo "Usage: ORGANIZATION_ID=\"12345\" ./scripts/setup_gcp_live_test.sh"
  exit 1
fi

PARENT_FLAG=""
if [ -n "${PARENT_FOLDER_ID}" ]; then
  PARENT_FLAG="--folder=${PARENT_FOLDER_ID}"
  echo -e "Using parent folder: ${PARENT_FOLDER_ID}"
else
  PARENT_FLAG="--organization=${ORGANIZATION_ID}"
  echo -e "Using organization: ${ORGANIZATION_ID}"
fi

# Define the 4 consolidated project IDs (must be globally unique in GCP)
# Using a short random suffix to prevent collisions
SUFFIX="${RANDOM}"
PROJ_STANDARD="${PROJECT_PREFIX}-std-${SUFFIX}"
PROJ_NO_CREATE="${PROJECT_PREFIX}-noc-${SUFFIX}"
PROJ_NO_UPLOAD="${PROJECT_PREFIX}-nou-${SUFFIX}"
PROJ_EXPIRY="${PROJECT_PREFIX}-exp-${SUFFIX}"

PROJECTS=(
  "${PROJ_STANDARD}"
  "${PROJ_NO_CREATE}"
  "${PROJ_NO_UPLOAD}"
  "${PROJ_EXPIRY}"
)

# ------------------------------------------------------------------------------
# 1. Create Dedicated Test Folder
# ------------------------------------------------------------------------------
FOLDER_NAME="sa-key-manager-ci"
echo -e "\n${GREEN}[1/6] Creating GCP Folder: ${FOLDER_NAME}...${NC}"
CI_FOLDER_ID=$(gcloud resource-manager folders create \
  --display-name="${FOLDER_NAME}" \
  ${PARENT_FLAG} \
  --format="value(name)" | sed 's|folders/||')
echo -e "Created folder ID: ${CI_FOLDER_ID}"

# ------------------------------------------------------------------------------
# 2. Create the 4 Consolidated Policy Projects
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[2/6] Creating 4 consolidated policy projects in folder ${CI_FOLDER_ID}...${NC}"
for PROJ in "${PROJECTS[@]}"; do
  echo "Creating project: ${PROJ}..."
  gcloud projects create "${PROJ}" --folder="${CI_FOLDER_ID}" --name="${PROJ}"

  echo "Enabling necessary APIs on ${PROJ}..."
  gcloud services enable \
    iam.googleapis.com \
    cloudresourcemanager.googleapis.com \
    orgpolicy.googleapis.com \
    iamcredentials.googleapis.com \
    --project="${PROJ}"
done

# ------------------------------------------------------------------------------
# 3. Configure Organization Policies on Respective Projects
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[3/6] Configuring Organization Policies...${NC}"

# A. Standard Project: Ensure no restrictive policies are enforced
echo "Configuring standard project (unrestricted)..."
gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyCreation --project="${PROJ_STANDARD}" || true
gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyUpload --project="${PROJ_STANDARD}" || true

# B. No-Create Project: Enforce constraints/iam.disableServiceAccountKeyCreation
echo "Configuring no-create project (enforcing disableServiceAccountKeyCreation)..."
gcloud resource-manager org-policies enable-enforce constraints/iam.disableServiceAccountKeyCreation --project="${PROJ_NO_CREATE}"

# C. No-Upload Project: Enforce constraints/iam.disableServiceAccountKeyUpload
echo "Configuring no-upload project (enforcing disableServiceAccountKeyUpload)..."
gcloud resource-manager org-policies enable-enforce constraints/iam.disableServiceAccountKeyUpload --project="${PROJ_NO_UPLOAD}"

# D. Expiry-24h Project: Enforce constraints/iam.serviceAccountKeyExpiryHours = 24h
echo "Configuring expiry project (enforcing serviceAccountKeyExpiryHours = 24h)..."
TMP_POLICY_FILE=$(mktemp)
cat << POLICY_EOF > "${TMP_POLICY_FILE}"
name: projects/${PROJ_EXPIRY}/policies/constraints/iam.serviceAccountKeyExpiryHours
spec:
  rules:
  - values:
      allowedValues:
      - "24h"
  inheritFromParent: false
POLICY_EOF

gcloud resource-manager org-policies set-policy "${TMP_POLICY_FILE}" --project="${PROJ_EXPIRY}"
rm -f "${TMP_POLICY_FILE}"

# ------------------------------------------------------------------------------
# 4. Create Per-Runner Service Accounts in Identity Project (PROJ_STANDARD)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[4/6] Creating 5 per-runner Service Accounts...${NC}"

RUNNER_NAMES=(
  "linux-amd64"
  "linux-arm64"
  "macos-arm64"
  "windows-amd64"
  "windows-arm64"
)

declare -A RUNNER_EMAILS

for RUNNER in "${RUNNER_NAMES[@]}"; do
  SA_NAME="sa-ci-${RUNNER}"
  SA_EMAIL="${SA_NAME}@${PROJ_STANDARD}.iam.gserviceaccount.com"
  RUNNER_EMAILS["${RUNNER}"]="${SA_EMAIL}"

  echo "Creating runner Service Account: ${SA_NAME}..."
  gcloud iam service-accounts create "${SA_NAME}" \
    --project="${PROJ_STANDARD}" \
    --display-name="CI Runner SA for ${RUNNER}"

  # Grant permissions across all 4 test projects
  echo "Granting IAM roles across the 4 test projects to ${SA_EMAIL}..."
  for PROJ in "${PROJECTS[@]}"; do
    gcloud projects add-iam-policy-binding "${PROJ}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="roles/iam.serviceAccountAdmin" \
      --quiet >/dev/null

    gcloud projects add-iam-policy-binding "${PROJ}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="roles/iam.serviceAccountKeyAdmin" \
      --quiet >/dev/null
  done
done

# ------------------------------------------------------------------------------
# 5. Configure Workload Identity Federation (WIF) for GitHub Actions
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[5/6] Setting up Workload Identity Federation (WIF)...${NC}"
POOL_ID="gh-actions-pool"
PROVIDER_ID="gh-oidc-provider"

PROJ_NUMBER=$(gcloud projects describe "${PROJ_STANDARD}" --format="value(projectNumber)")

# Create Pool
echo "Creating Workload Identity Pool: ${POOL_ID}..."
gcloud iam workload-identity-pools create "${POOL_ID}" \
  --project="${PROJ_STANDARD}" \
  --location="global" \
  --display-name="GitHub Actions Pool" \
  --description="Workload Identity Pool for GitHub Actions runners" || true

# Create Provider
echo "Creating OIDC Provider: ${PROVIDER_ID}..."
gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_ID}" \
  --project="${PROJ_STANDARD}" \
  --location="global" \
  --workload-identity-pool="${POOL_ID}" \
  --display-name="GitHub OIDC Provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" || true

# Bind each runner Service Account to the GitHub repository
WIF_PROVIDER_RESOURCE="projects/${PROJ_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"
echo -e "WIF Provider Resource: ${WIF_PROVIDER_RESOURCE}"

for RUNNER in "${RUNNER_NAMES[@]}"; do
  SA_EMAIL="${RUNNER_EMAILS[${RUNNER}]}"
  echo "Authorizing GitHub repo ${GITHUB_REPO} to impersonate ${SA_EMAIL}..."
  gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJ_STANDARD}" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/${PROJ_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository/${GITHUB_REPO}" \
    --quiet >/dev/null
done

# ------------------------------------------------------------------------------
# 6. Output Summary and GitHub Repository Configuration
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}================================================================${NC}"
echo -e "${GREEN}Provisioning Complete!${NC}"
echo -e "${BLUE}================================================================${NC}"

echo -e "\nAdd the following ${YELLOW}Variables${NC} to your GitHub repository:"
echo "Repository Settings -> Secrets and variables -> Actions -> Variables:"
echo "------------------------------------------------------------------"
echo "GCP_WIF_PROVIDER=${WIF_PROVIDER_RESOURCE}"
echo "GCP_PROJECT_STANDARD=${PROJ_STANDARD}"
echo "GCP_PROJECT_NO_CREATE=${PROJ_NO_CREATE}"
echo "GCP_PROJECT_NO_UPLOAD=${PROJ_NO_UPLOAD}"
echo "GCP_PROJECT_EXPIRY_24H=${PROJ_EXPIRY}"
echo "GCP_SA_LINUX_AMD64=${RUNNER_EMAILS[linux-amd64]}"
echo "GCP_SA_LINUX_ARM64=${RUNNER_EMAILS[linux-arm64]}"
echo "GCP_SA_MACOS_ARM64=${RUNNER_EMAILS[macos-arm64]}"
echo "GCP_SA_WINDOWS_AMD64=${RUNNER_EMAILS[windows-amd64]}"
echo "GCP_SA_WINDOWS_ARM64=${RUNNER_EMAILS[windows-arm64]}"
echo "------------------------------------------------------------------"

echo -e "\nTo clean up these test projects in the future, run:"
echo "./scripts/cleanup_gcp_live_test.sh ${PROJ_STANDARD} ${PROJ_NO_CREATE} ${PROJ_NO_UPLOAD} ${PROJ_EXPIRY} ${CI_FOLDER_ID}"
