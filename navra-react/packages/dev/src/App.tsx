import React, { useState } from "react";
import {
  Page,
  PageSection,
  Masthead,
  MastheadMain,
  MastheadBrand,
  Content,
  Tabs,
  Tab,
  TabTitleText,
} from "@patternfly/react-core";
import { MetricsPanel } from "./panels/MetricsPanel";
import { ApprovalPanel } from "./panels/ApprovalPanel";
import { ActivityPanel } from "./panels/ActivityPanel";
import { SecurityPanel } from "./panels/SecurityPanel";
import { FlowPanel } from "./panels/FlowPanel";

export function App() {
  const [activeTab, setActiveTab] = useState(0);

  return (
    <Page
      masthead={
        <Masthead>
          <MastheadMain>
            <MastheadBrand>navra dashboard</MastheadBrand>
          </MastheadMain>
        </Masthead>
      }
    >
      <PageSection>
        <Content component="h1">navra Dashboard</Content>
        <Content component="p">
          Development preview — connect to a running navra instance or use mock
          data.
        </Content>
      </PageSection>
      <PageSection>
        <Tabs
          activeKey={activeTab}
          onSelect={(_e, key) => setActiveTab(key as number)}
        >
          <Tab eventKey={0} title={<TabTitleText>Metrics</TabTitleText>}>
            <PageSection>
              <MetricsPanel />
            </PageSection>
          </Tab>
          <Tab eventKey={1} title={<TabTitleText>Approvals</TabTitleText>}>
            <PageSection>
              <ApprovalPanel />
            </PageSection>
          </Tab>
          <Tab eventKey={2} title={<TabTitleText>Security</TabTitleText>}>
            <PageSection>
              <SecurityPanel />
            </PageSection>
          </Tab>
          <Tab eventKey={3} title={<TabTitleText>Flow</TabTitleText>}>
            <PageSection>
              <FlowPanel />
            </PageSection>
          </Tab>
          <Tab eventKey={4} title={<TabTitleText>Activity</TabTitleText>}>
            <PageSection>
              <ActivityPanel />
            </PageSection>
          </Tab>
        </Tabs>
      </PageSection>
    </Page>
  );
}
