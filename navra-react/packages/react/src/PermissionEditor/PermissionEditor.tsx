import React, { useCallback, useMemo, useState } from "react";
import {
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  TextInput,
  FormGroup,
  Form,
  Button,
  Label,
  Alert,
  Select,
  SelectOption,
  MenuToggle,
  Switch,
  Content,
  Flex,
  FlexItem,
} from "@patternfly/react-core";
import { Table, Thead, Tr, Th, Tbody, Td } from "@patternfly/react-table";
import { PlusCircleIcon, TrashIcon } from "@patternfly/react-icons";
import {
  type PermissionSet,
  type PermissionConfig,
  type ToolRule,
  permissionSetToToml,
  validatePermissionSet,
  defaultPermissionSet,
} from "./types";

export interface PermissionEditorProps {
  config: PermissionConfig;
  onChange?: (config: PermissionConfig) => void;
  readOnly?: boolean;
}

function PathList({
  label,
  paths,
  color,
  onAdd,
  onRemove,
  readOnly,
}: {
  label: string;
  paths: string[];
  color: "green" | "red" | "orange";
  onAdd: (path: string) => void;
  onRemove: (index: number) => void;
  readOnly?: boolean;
}) {
  const [draft, setDraft] = useState("");

  return (
    <FormGroup label={label}>
      <Flex direction={{ default: "column" }} gap={{ default: "gapSm" }}>
        {paths.map((p, i) => (
          <FlexItem key={i}>
            <Flex gap={{ default: "gapSm" }} alignItems={{ default: "alignItemsCenter" }}>
              <FlexItem>
                <Label isCompact color={color}>
                  {p}
                </Label>
              </FlexItem>
              {!readOnly && (
                <FlexItem>
                  <Button
                    variant="plain"
                    size="sm"
                    icon={<TrashIcon />}
                    onClick={() => onRemove(i)}
                  />
                </FlexItem>
              )}
            </Flex>
          </FlexItem>
        ))}
        {!readOnly && (
          <FlexItem>
            <Flex gap={{ default: "gapSm" }}>
              <FlexItem grow={{ default: "grow" }}>
                <TextInput
                  value={draft}
                  onChange={(_e, val) => setDraft(val)}
                  placeholder="~/path/to/dir/**"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && draft.trim()) {
                      onAdd(draft.trim());
                      setDraft("");
                    }
                  }}
                />
              </FlexItem>
              <FlexItem>
                <Button
                  variant="plain"
                  icon={<PlusCircleIcon />}
                  isDisabled={!draft.trim()}
                  onClick={() => {
                    onAdd(draft.trim());
                    setDraft("");
                  }}
                />
              </FlexItem>
            </Flex>
          </FlexItem>
        )}
      </Flex>
    </FormGroup>
  );
}

function PermissionSetEditor({
  name,
  ps,
  onChange,
  readOnly,
}: {
  name: string;
  ps: PermissionSet;
  onChange: (ps: PermissionSet) => void;
  readOnly?: boolean;
}) {
  const warnings = useMemo(() => validatePermissionSet(ps), [ps]);
  const toml = useMemo(() => permissionSetToToml(name, ps), [name, ps]);

  const [safetyOpen, setSafetyOpen] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(false);
  const [taintOpen, setTaintOpen] = useState(false);

  const addPath = useCallback(
    (field: "allow" | "deny" | "trustedPaths", path: string) => {
      onChange({ ...ps, [field]: [...ps[field], path] });
    },
    [ps, onChange],
  );

  const removePath = useCallback(
    (field: "allow" | "deny" | "trustedPaths", index: number) => {
      onChange({ ...ps, [field]: ps[field].filter((_, i) => i !== index) });
    },
    [ps, onChange],
  );

  const addToolRule = useCallback(() => {
    onChange({
      ...ps,
      toolRules: [...ps.toolRules, { tool: "*", policy: "allow" }],
    });
  }, [ps, onChange]);

  const removeToolRule = useCallback(
    (index: number) => {
      onChange({
        ...ps,
        toolRules: ps.toolRules.filter((_, i) => i !== index),
      });
    },
    [ps, onChange],
  );

  const updateToolRule = useCallback(
    (index: number, rule: ToolRule) => {
      const rules = [...ps.toolRules];
      rules[index] = rule;
      onChange({ ...ps, toolRules: rules });
    },
    [ps, onChange],
  );

  return (
    <Grid hasGutter>
      <GridItem span={8}>
        <Card>
          <CardTitle>{name}</CardTitle>
          <CardBody>
            <Form>
              <Grid hasGutter>
                <GridItem span={4}>
                  <FormGroup label="Ring">
                    <TextInput
                      type="number"
                      value={ps.ring ?? ""}
                      onChange={(_e, val) =>
                        onChange({
                          ...ps,
                          ring: val === "" ? undefined : Number(val),
                        })
                      }
                      isDisabled={readOnly}
                      placeholder="0-3"
                    />
                  </FormGroup>
                </GridItem>
                <GridItem span={4}>
                  <FormGroup label="Safety">
                    <Select
                      toggle={(ref) => (
                        <MenuToggle
                          ref={ref}
                          onClick={() => setSafetyOpen(!safetyOpen)}
                          isExpanded={safetyOpen}
                          isDisabled={readOnly}
                        >
                          {ps.safety}
                        </MenuToggle>
                      )}
                      isOpen={safetyOpen}
                      onSelect={(_e, val) => {
                        onChange({ ...ps, safety: val as string });
                        setSafetyOpen(false);
                      }}
                      selected={ps.safety}
                      onOpenChange={setSafetyOpen}
                    >
                      {[
                        "standard",
                        "pseudonymize",
                        "secrets-only",
                        "multi-label",
                        "guardian",
                        "guardian-deep",
                        "block",
                        "none",
                      ].map((s) => (
                        <SelectOption key={s} value={s}>
                          {s}
                        </SelectOption>
                      ))}
                    </Select>
                  </FormGroup>
                </GridItem>
                <GridItem span={4}>
                  <FormGroup label="Tainted Write Policy">
                    <Select
                      toggle={(ref) => (
                        <MenuToggle
                          ref={ref}
                          onClick={() => setTaintOpen(!taintOpen)}
                          isExpanded={taintOpen}
                          isDisabled={readOnly}
                        >
                          {ps.taintedWritePolicy}
                        </MenuToggle>
                      )}
                      isOpen={taintOpen}
                      onSelect={(_e, val) => {
                        onChange({
                          ...ps,
                          taintedWritePolicy: val as string,
                        });
                        setTaintOpen(false);
                      }}
                      selected={ps.taintedWritePolicy}
                      onOpenChange={setTaintOpen}
                    >
                      {["allow", "approve", "deny"].map((s) => (
                        <SelectOption key={s} value={s}>
                          {s}
                        </SelectOption>
                      ))}
                    </Select>
                  </FormGroup>
                </GridItem>
              </Grid>

              <PathList
                label="Allow paths"
                paths={ps.allow}
                color="green"
                onAdd={(p) => addPath("allow", p)}
                onRemove={(i) => removePath("allow", i)}
                readOnly={readOnly}
              />
              <PathList
                label="Deny paths"
                paths={ps.deny}
                color="red"
                onAdd={(p) => addPath("deny", p)}
                onRemove={(i) => removePath("deny", i)}
                readOnly={readOnly}
              />

              <FormGroup label="Operations">
                <Flex gap={{ default: "gapSm" }} flexWrap={{ default: "wrap" }}>
                  {ps.operations.map((op) => (
                    <FlexItem key={op}>
                      <Label
                        isCompact
                        color={ps.approve.includes(op) ? "orange" : "blue"}
                      >
                        {op}
                        {ps.approve.includes(op) && " (approve)"}
                      </Label>
                    </FlexItem>
                  ))}
                </Flex>
              </FormGroup>

              <FormGroup label="Tool Rules">
                <Table aria-label="Tool rules" variant="compact">
                  <Thead>
                    <Tr>
                      <Th>Pattern</Th>
                      <Th>Policy</Th>
                      {!readOnly && <Th />}
                    </Tr>
                  </Thead>
                  <Tbody>
                    {ps.toolRules.map((rule, i) => (
                      <Tr key={i}>
                        <Td>
                          <TextInput
                            value={rule.tool}
                            onChange={(_e, val) =>
                              updateToolRule(i, { ...rule, tool: val })
                            }
                            isDisabled={readOnly}
                          />
                        </Td>
                        <Td>
                          <Label
                            isCompact
                            color={
                              rule.policy === "deny"
                                ? "red"
                                : rule.policy === "approve"
                                  ? "orange"
                                  : "green"
                            }
                          >
                            {rule.policy}
                          </Label>
                        </Td>
                        {!readOnly && (
                          <Td>
                            <Button
                              variant="plain"
                              size="sm"
                              icon={<TrashIcon />}
                              onClick={() => removeToolRule(i)}
                            />
                          </Td>
                        )}
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
                {!readOnly && (
                  <Button
                    variant="link"
                    icon={<PlusCircleIcon />}
                    onClick={addToolRule}
                  >
                    Add rule
                  </Button>
                )}
              </FormGroup>

              <FormGroup label="Default Tool Policy">
                <Select
                  toggle={(ref) => (
                    <MenuToggle
                      ref={ref}
                      onClick={() => setPolicyOpen(!policyOpen)}
                      isExpanded={policyOpen}
                      isDisabled={readOnly}
                    >
                      {ps.defaultToolPolicy}
                    </MenuToggle>
                  )}
                  isOpen={policyOpen}
                  onSelect={(_e, val) => {
                    onChange({ ...ps, defaultToolPolicy: val as string });
                    setPolicyOpen(false);
                  }}
                  selected={ps.defaultToolPolicy}
                  onOpenChange={setPolicyOpen}
                >
                  {["allow", "deny", "approve"].map((s) => (
                    <SelectOption key={s} value={s}>
                      {s}
                    </SelectOption>
                  ))}
                </Select>
              </FormGroup>

              <Switch
                id={`${name}-delegate`}
                label="Can delegate capabilities"
                isChecked={ps.canDelegate}
                onChange={(_e, val) => onChange({ ...ps, canDelegate: val })}
                isDisabled={readOnly}
              />
            </Form>

            {warnings.length > 0 && (
              <div style={{ marginTop: 16 }}>
                {warnings.map((w, i) => (
                  <Alert
                    key={i}
                    variant="warning"
                    isInline
                    isPlain
                    title={w.message}
                  />
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={4}>
        <Card>
          <CardTitle>TOML Preview</CardTitle>
          <CardBody>
            <pre
              style={{
                fontSize: 12,
                fontFamily: "RedHatMono, monospace",
                background: "#f0f0f0",
                padding: 12,
                borderRadius: 4,
                overflow: "auto",
                maxHeight: 600,
                whiteSpace: "pre-wrap",
              }}
            >
              {toml}
            </pre>
          </CardBody>
        </Card>
      </GridItem>
    </Grid>
  );
}

export function PermissionEditor({
  config,
  onChange,
  readOnly = false,
}: PermissionEditorProps) {
  const names = Object.keys(config);

  const handleChange = useCallback(
    (name: string, ps: PermissionSet) => {
      onChange?.({ ...config, [name]: ps });
    },
    [config, onChange],
  );

  if (names.length === 0) {
    return <Content>No permission sets configured.</Content>;
  }

  return (
    <Flex direction={{ default: "column" }} gap={{ default: "gapLg" }}>
      {names.map((name) => (
        <FlexItem key={name}>
          <PermissionSetEditor
            name={name}
            ps={config[name]}
            onChange={(ps) => handleChange(name, ps)}
            readOnly={readOnly}
          />
        </FlexItem>
      ))}
    </Flex>
  );
}
