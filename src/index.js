import React, { useState } from "react";
import "./index.css";
import { Tab, Tabs } from "@mui/material";
import DataGrid from "./components/grid/vulnerability-report";
import Dashboard from "./components/dashboard/dashboard";

// Helper function to create CRC32 hash for Trivy report naming (when names are too long)
const computeHash = (str) => {
  let crc = 0 ^ -1;
  for (let i = 0; i < str.length; i++) {
    crc = (crc >>> 8) ^ ((crc ^ str.charCodeAt(i)) & 0xff);
  }
  return ((crc ^ -1) >>> 0).toString(16).slice(-10).padStart(10, "0");
};

// Helper function to build VulnerabilityReport name with Trivy 0.29.0+ naming convention
const buildReportName = (
  resourceKind,
  resourceName,
  containerName,
  podHash = ""
) => {
  let reportName = `${resourceKind}-${resourceName}`;
  if (podHash) {
    reportName += `-${podHash}`;
  }
  reportName += `-${containerName}`;

  // Kubernetes label values have a 63 character limit
  // If name exceeds limit, use hash fallback like Trivy does
  if (reportName.length > 63) {
    const hashInput = `${resourceName}-${containerName}`;
    reportName = `${resourceKind}-${computeHash(hashInput)}`;
  }

  return reportName;
};

const Extension = (props) => {
  const { resource, application } = props;
  const appName = application?.metadata?.name || "";
  const resourceNamespace = resource?.metadata?.namespace || "";
  const isPod = resource?.kind === "Pod";
  const isCronJob = resource?.kind === "CronJob";
  const resourceName = isPod
    ? resource?.metadata?.ownerReferences[0].name.toLowerCase()
    : resource?.metadata?.name;
  const resourceKind = isPod
    ? resource?.metadata?.ownerReferences[0].kind.toLowerCase()
    : resource?.kind?.toLowerCase();

  // Get pod hash (revision hash from pod name if available)
  const podHash = isPod
    ? resource?.metadata?.name?.match(/-([a-z0-9]{10})$/)?.[1] || ""
    : "";

  let [containerName] = useState(
    isPod
      ? resource?.spec?.containers[0]?.name
      : isCronJob
      ? resource?.spec?.jobTemplate?.spec?.template?.spec.containers[0]?.name
      : resource?.spec?.template?.spec?.containers[0]?.name
  );

  const baseURI = `${window.location.origin}/api/v1/applications/${appName}/resource`;

  // Build report name using Trivy 0.29.0+ naming convention
  const reportName = buildReportName(
    resourceKind,
    resourceName,
    containerName,
    podHash
  );
  let [reportUrl, setReportUrl] = useState(
    `${baseURI}?name=${reportName}&namespace=${resourceNamespace}&resourceName=${reportName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`
  );

  let containers = [];
  if (isPod) {
    containers = [
      ...resource?.spec?.containers,
      ...(resource.spec?.initContainers ?? []),
    ];
  } else if (isCronJob) {
    containers = [
      ...resource?.spec?.jobTemplate?.spec?.template?.spec.containers,
      ...(resource?.spec?.jobTemplate?.spec?.template?.spec.initContainers ??
        []),
    ];
  } else {
    containers = [
      ...resource?.spec?.template?.spec.containers,
      ...(resource?.spec?.template?.spec.initContainers ?? []),
    ];
  }

  const containerNames = containers.map((c) => c.name);
  const images = containers.map((c) => c.image);

  const [currentTabIndex, setCurrentTabIndex] = useState(0);
  const handleTabChange = (_e, tabIndex) => {
    setCurrentTabIndex(tabIndex);
  };

  const onOptionChangeHandler = (event) => {
    containerName = event.target.value;
    const reportName = buildReportName(
      resourceKind,
      resourceName,
      containerName,
      podHash
    );
    setReportUrl(
      `${baseURI}?name=${reportName}&namespace=${resourceNamespace}&resourceName=${reportName}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`
    );
  };

  return (
    <div>
      <React.Fragment>
        <select
          class="vulnerability-report__container_dropdown"
          onChange={onOptionChangeHandler}
        >
          {containerNames.map((container, index) => {
            return (
              <option
                key={index}
                value={container}
              >{`${container} (${images[index]})`}</option>
            );
          })}
        </select>
        <Tabs value={currentTabIndex} onChange={handleTabChange}>
          <Tab label="Table" />
          <Tab label="Dashboard" />
        </Tabs>
        {currentTabIndex === 0 && <DataGrid reportUrl={reportUrl} />}
        {currentTabIndex === 1 && <Dashboard reportUrl={reportUrl} />}
      </React.Fragment>
    </div>
  );
};

const component = Extension;

((window) => {
  window?.extensionsAPI?.registerResourceExtension(
    component,
    "*",
    "ReplicaSet",
    "Vulnerabilities",
    { icon: "fa fa-triangle-exclamation" }
  );
  window?.extensionsAPI?.registerResourceExtension(
    component,
    "",
    "Pod",
    "Vulnerabilities",
    { icon: "fa fa-triangle-exclamation" }
  );
  window?.extensionsAPI?.registerResourceExtension(
    component,
    "*",
    "StatefulSet",
    "Vulnerabilities",
    { icon: "fa fa-triangle-exclamation" }
  );
  window?.extensionsAPI?.registerResourceExtension(
    component,
    "*",
    "CronJob",
    "Vulnerabilities",
    { icon: "fa fa-triangle-exclamation" }
  );
})(window);
