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
#   - Note: To enforce Organization Policies, roles/orgpolicy.policyAdmin must be granted
#     at the Organization level.

set -uo pipefail

# ------------------------------------------------------------------------------
# Configuration & Inputs
# ------------------------------------------------------------------------------
CI_FOLDER_ID="${CI_FOLDER_ID:-}"               # Existing test folder ID if resuming (e.g., "442607557716")
PARENT_FOLDER_ID="${PARENT_FOLDER_ID:-}"       # e.g., "123456789012" (leave empty if using ORG_ID)
ORGANIZATION_ID="${ORGANIZATION_ID:-}"         # e.g., "123456789012" (leave empty if using PARENT_FOLDER_ID)
PROJECT_PREFIX="${PROJECT_PREFIX:-sakm-ci}"    # Prefix for test projects
SUFFIX="${SUFFIX:-${RANDOM}}"                  # Suffix for project names (pass existing suffix to resume)
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
if [ -z "${CI_FOLDER_ID}" ] && [ -z "${PARENT_FOLDER_ID}" ] && [ -z "${ORGANIZATION_ID}" ]; then
  echo -e "${RED}ERROR: Either CI_FOLDER_ID, PARENT_FOLDER_ID, or ORGANIZATION_ID must be provided.${NC}"
  echo "Usage: ORGANIZATION_ID=\"12345\" ./scripts/setup_gcp_live_test.sh"
  exit 1
fi

PARENT_FLAG=""
if [ -n "${PARENT_FOLDER_ID}" ]; then
  PARENT_FLAG="--folder=${PARENT_FOLDER_ID}"
  echo -e "Using parent folder: ${PARENT_FOLDER_ID}"
elif [ -n "${ORGANIZATION_ID}" ]; then
  PARENT_FLAG="--organization=${ORGANIZATION_ID}"
  echo -e "Using organization: ${ORGANIZATION_ID}"
fi

# Define the 4 consolidated project IDs
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
# 1. Create Dedicated Test Folder (if not already provided)
# ------------------------------------------------------------------------------
if [ -n "${CI_FOLDER_ID}" ]; then
  echo -e "\n${GREEN}[1/6] Using existing GCP Folder ID: ${CI_FOLDER_ID}...${NC}"
else
  FOLDER_NAME="sa-key-manager-ci"
  echo -e "\n${GREEN}[1/6] Creating GCP Folder: ${FOLDER_NAME}...${NC}"
  CI_FOLDER_ID=$(gcloud resource-manager folders create \
    --display-name="${FOLDER_NAME}" \
    ${PARENT_FLAG} \
    --format="value(name)" | sed 's|folders/||')
  echo -e "Created folder ID: ${CI_FOLDER_ID}"
fi

# ------------------------------------------------------------------------------
# 2. Create the 4 Consolidated Policy Projects (Idempotent)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[2/6] Ensuring 4 consolidated policy projects exist in folder ${CI_FOLDER_ID}...${NC}"
for PROJ in "${PROJECTS[@]}"; do
  if gcloud projects describe "${PROJ}" &>/dev/null; then
    echo "Project ${PROJ} already exists. Skipping creation."
  else
    echo "Creating project: ${PROJ}..."
    gcloud projects create "${PROJ}" --folder="${CI_FOLDER_ID}" --name="${PROJ}"
  fi

  echo "Ensuring necessary APIs are enabled on ${PROJ}..."
  gcloud services enable \
    iam.googleapis.com \
    cloudresourcemanager.googleapis.com \
    orgpolicy.googleapis.com \
    iamcredentials.googleapis.com \
    --project="${PROJ}" --quiet
done

# ------------------------------------------------------------------------------
# 3. Configure Organization Policies on Respective Projects
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[3/6] Configuring Organization Policies...${NC}"

CURRENT_ACCOUNT=$(gcloud config get-value account 2>/dev/null || echo "your account")

apply_policy_safely() {
  local CMD="$1"
  local PROJ_DESC="$2"
  echo "Applying policy for ${PROJ_DESC}..."
  if ! eval "${CMD}" 2>/tmp/org_policy_err.log; then
    echo -e "${YELLOW}[WARNING] Could not set Organization Policy for ${PROJ_DESC}.${NC}"
    echo -e "${YELLOW}Reason:${NC} $(cat /tmp/org_policy_err.log | grep -i 'permission' || cat /tmp/org_policy_err.log | head -n 2)"
    echo -e "${YELLOW}To enforce Organization Policies, an Organization Admin must grant:${NC}"
    echo -e "  gcloud organizations add-iam-policy-binding <ORG_ID> \\"
    echo -e "    --member=\"user:${CURRENT_ACCOUNT}\" \\"
    echo -e "    --role=\"roles/orgpolicy.policyAdmin\""
    echo -e "${YELLOW}Continuing with Service Account and WIF setup...${NC}\n"
  else
    echo -e "${GREEN}Policy applied successfully.${NC}"
  fi
  rm -f /tmp/org_policy_err.log
}

# A. Standard Project: Ensure no restrictive policies are enforced
apply_policy_safely "gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyCreation --project=${PROJ_STANDARD} && gcloud resource-manager org-policies disable-enforce constraints/iam.disableServiceAccountKeyUpload --project=${PROJ_STANDARD}" "standard project (unrestricted)"

# B. No-Create Project: Enforce constraints/iam.disableServiceAccountKeyCreation
apply_policy_safely "gcloud resource-manager org-policies enable-enforce constraints/iam.disableServiceAccountKeyCreation --project=${PROJ_NO_CREATE}" "no-create project (disableServiceAccountKeyCreation)"

# C. No-Upload Project: Enforce constraints/iam.disableServiceAccountKeyUpload
apply_policy_safely "gcloud resource-manager org-policies enable-enforce constraints/iam.disableServiceAccountKeyUpload --project=${PROJ_NO_UPLOAD}" "no-upload project (disableServiceAccountKeyUpload)"

# D. Expiry-24h Project: Enforce constraints/iam.serviceAccountKeyExpiryHours = 24h
TMP_POLICY_V1=$(mktemp)
cat << POLICY_EOF > "${TMP_POLICY_V1}"
constraint: constraints/iam.serviceAccountKeyExpiryHours
listPolicy:
  allowedValues:
  - "24h"
POLICY_EOF

TMP_POLICY_V2=$(mktemp)
cat << POLICY_EOF > "${TMP_POLICY_V2}"
name: projects/${PROJ_EXPIRY}/policies/constraints/iam.serviceAccountKeyExpiryHours
spec:
  rules:
  - values:
      allowedValues:
      - "24h"
  inheritFromParent: false
POLICY_EOF

apply_policy_safely "gcloud resource-manager org-policies set-policy ${TMP_POLICY_V1} --project=${PROJ_EXPIRY} || gcloud org-policies set-policy ${TMP_POLICY_V2}" "expiry project (serviceAccountKeyExpiryHours=24h)"
rm -f "${TMP_POLICY_V1}" "${TMP_POLICY_V2}"

# ------------------------------------------------------------------------------
# 4. Create Per-Runner Service Accounts in Identity Project (PROJ_STANDARD)
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}[4/6] Ensuring 5 per-runner Service Accounts exist in ${PROJ_STANDARD}...${NC}"

RUNNER_NAMES=(
  "linux-amd64"
  "linux-arm64"
  "macos-arm64"
  "windows-amd64"
  "windows-arm64"
)

for RUNNER in "${RUNNER_NAMES[@]}"; do
  SA_NAME="sa-ci-${RUNNER}"
  SA_EMAIL="${SA_NAME}@${PROJ_STANDARD}.iam.gserviceaccount.com"

  if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJ_STANDARD}" &>/dev/null; then
    echo "Service Account ${SA_NAME} already exists."
  else
    echo "Creating runner Service Account: ${SA_NAME}..."
    gcloud iam service-accounts create "${SA_NAME}" \
      --project="${PROJ_STANDARD}" \
      --display-name="CI Runner SA for ${RUNNER}"
  fi

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

# Create Pool if it doesn't exist
if ! gcloud iam workload-identity-pools describe "${POOL_ID}" --project="${PROJ_STANDARD}" --location="global" &>/dev/null; then
  echo "Creating Workload Identity Pool: ${POOL_ID}..."
  gcloud iam workload-identity-pools create "${POOL_ID}" \
    --project="${PROJ_STANDARD}" \
    --location="global" \
    --display-name="GitHub Actions Pool" \
    --description="Workload Identity Pool for GitHub Actions runners"
else
  echo "Workload Identity Pool ${POOL_ID} already exists."
fi

# Create Provider if it doesn't exist
if ! gcloud iam workload-identity-pools providers describe "${PROVIDER_ID}" --project="${PROJ_STANDARD}" --location="global" --workload-identity-pool="${POOL_ID}" &>/dev/null; then
  echo "Creating OIDC Provider: ${PROVIDER_ID}..."
  gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_ID}" \
    --project="${PROJ_STANDARD}" \
    --location="global" \
    --workload-identity-pool="${POOL_ID}" \
    --display-name="GitHub OIDC Provider" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner"
else
  echo "OIDC Provider ${PROVIDER_ID} already exists."
fi

# Bind each runner Service Account to the GitHub repository
WIF_PROVIDER_RESOURCE="projects/${PROJ_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"
echo -e "WIF Provider Resource: ${WIF_PROVIDER_RESOURCE}"

for RUNNER in "${RUNNER_NAMES[@]}"; do
  SA_EMAIL="sa-ci-${RUNNER}@${PROJ_STANDARD}.iam.gserviceaccount.com"
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
for RUNNER in "${RUNNER_NAMES[@]}"; do
  VAR_NAME="GCP_SA_$(echo "${RUNNER}" | tr '[:lower:]-' '[:upper:]_')"
  echo "${VAR_NAME}=sa-ci-${RUNNER}@${PROJ_STANDARD}.iam.gserviceaccount.com"
done
echo "------------------------------------------------------------------"

echo -e "\nTo clean up these test projects in the future, run:"
echo "./scripts/cleanup_gcp_live_test.sh ${PROJ_STANDARD} ${PROJ_NO_CREATE} ${PROJ_NO_UPLOAD} ${PROJ_EXPIRY} ${CI_FOLDER_ID}"
