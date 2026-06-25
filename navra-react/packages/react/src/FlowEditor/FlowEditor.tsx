import React, { useState, useRef, useCallback } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
  Background,
  Controls,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  type Connection,
  type OnConnect,
  type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { TextArea } from "@patternfly/react-core";
import {
  graphToYaml,
  yamlToGraph,
  useFlowValidation,
  type FlowMeta,
} from "@navra/react-hooks";
import { EditorNode, type EditorNodeData } from "./EditorNode";
import { NodePalette } from "./NodePalette";
import { NodeConfigPanel } from "./NodeConfigPanel";
import { FlowEditorToolbar } from "./FlowEditorToolbar";

export interface FlowEditorProps {
  initialYaml?: string;
  onSave?: (yaml: string) => void;
  onLoad?: () => void;
  height?: number | string;
}

const nodeTypes = { editor: EditorNode };

function FlowEditorInner({
  initialYaml,
  onSave,
  onLoad,
  height = 600,
}: FlowEditorProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNode, setSelectedNode] = useState<{
    id: string;
    data: Record<string, unknown>;
  } | null>(null);
  const [flowMeta, setFlowMeta] = useState<FlowMeta>({
    kind: "dag",
    name: "New Flow",
  });
  const [showYaml, setShowYaml] = useState(false);
  const [yamlContent, setYamlContent] = useState("");

  const nodeCounter = useRef(1);

  const { errors, isValid } = useFlowValidation({
    nodes,
    edges,
    kind: flowMeta.kind,
    entry: flowMeta.entry,
  });

  const errorCount = errors.filter((e) => e.severity === "error").length;

  const buildYaml = useCallback(() => {
    return graphToYaml(nodes, edges, flowMeta);
  }, [nodes, edges, flowMeta]);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      const data = event.dataTransfer.getData("application/json");
      if (!data) return;

      const item = JSON.parse(data);
      const reactFlowBounds = (
        event.currentTarget as HTMLElement
      ).getBoundingClientRect();
      const position = {
        x: event.clientX - reactFlowBounds.left,
        y: event.clientY - reactFlowBounds.top,
      };

      const nodeId = `node-${nodeCounter.current++}`;
      const newNode: Node = {
        id: nodeId,
        type: "editor",
        position,
        data: {
          label: nodeId,
          nodeType: flowMeta.kind,
          ...item.defaults,
        } as EditorNodeData,
      };

      setNodes((nds) => [...nds, newNode]);
    },
    [flowMeta.kind, setNodes],
  );

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  }, []);

  const onConnect: OnConnect = useCallback(
    (connection: Connection) => {
      if (connection.source && connection.target) {
        const newEdge: Edge = {
          id: `${connection.source}-${connection.target}`,
          source: connection.source,
          target: connection.target,
        };
        setEdges((eds) => [...eds, newEdge]);
      }
    },
    [setEdges],
  );

  const onNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      setSelectedNode({ id: node.id, data: node.data });
      setNodes((nds) =>
        nds.map((n) =>
          n.id === node.id
            ? { ...n, data: { ...n.data, selected: true } }
            : { ...n, data: { ...n.data, selected: false } },
        ),
      );
    },
    [setNodes],
  );

  const handleNodeConfigChange = useCallback(
    (nodeId: string, data: Record<string, unknown>) => {
      setNodes((nds) =>
        nds.map((n) => (n.id === nodeId ? { ...n, data } : n)),
      );
      setSelectedNode({ id: nodeId, data });
    },
    [setNodes],
  );

  const handleNodeConfigClose = useCallback(() => {
    setSelectedNode(null);
    setNodes((nds) =>
      nds.map((n) => ({ ...n, data: { ...n.data, selected: false } })),
    );
  }, [setNodes]);

  const handleKindChange = useCallback(
    (kind: "dag" | "handoff") => {
      if (nodes.length > 0) {
        const confirmed = window.confirm(
          "Changing flow kind will clear the canvas. Continue?",
        );
        if (!confirmed) return;
        setNodes([]);
        setEdges([]);
      }
      setFlowMeta((m) => ({ ...m, kind }));
    },
    [nodes.length, setNodes, setEdges],
  );

  const handleSave = useCallback(() => {
    const yaml = buildYaml();
    setYamlContent(yaml);
    onSave?.(yaml);
  }, [buildYaml, onSave]);

  const handleToggleYaml = useCallback(() => {
    if (!showYaml) {
      setYamlContent(buildYaml());
    }
    setShowYaml((s) => !s);
  }, [showYaml, buildYaml]);

  const handleYamlChange = useCallback(
    (_event: React.ChangeEvent<HTMLTextAreaElement>, value: string) => {
      setYamlContent(value);
      const graph = yamlToGraph(value);
      if (graph.nodes.length > 0 || value.trim() === "") {
        setNodes(graph.nodes as Node[]);
        setEdges(graph.edges as Edge[]);
        setFlowMeta(graph.flowMeta);
      }
    },
    [setNodes, setEdges],
  );

  React.useEffect(() => {
    if (initialYaml) {
      const graph = yamlToGraph(initialYaml);
      setNodes(graph.nodes as Node[]);
      setEdges(graph.edges as Edge[]);
      setFlowMeta(graph.flowMeta);
      setYamlContent(initialYaml);
    }
  }, [initialYaml, setNodes, setEdges]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height,
        fontFamily: "RedHatText, Overpass, sans-serif",
      }}
    >
      <FlowEditorToolbar
        kind={flowMeta.kind}
        flowName={flowMeta.name}
        onKindChange={handleKindChange}
        onFlowNameChange={(name) => setFlowMeta((m) => ({ ...m, name }))}
        onSave={handleSave}
        onLoad={onLoad || (() => {})}
        onToggleYaml={handleToggleYaml}
        showYaml={showYaml}
        validationErrorCount={errorCount}
      />

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        <NodePalette kind={flowMeta.kind} />

        <div
          style={{ flex: 1, position: "relative" }}
          onDrop={onDrop}
          onDragOver={onDragOver}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
            <Controls />
          </ReactFlow>
        </div>

        {selectedNode && (
          <NodeConfigPanel
            node={selectedNode}
            kind={flowMeta.kind}
            onChange={handleNodeConfigChange}
            onClose={handleNodeConfigClose}
            validationErrors={errors.filter(
              (e) => e.nodeIds?.includes(selectedNode.id),
            )}
          />
        )}
      </div>

      {showYaml && (
        <div
          style={{
            height: 200,
            borderTop: "1px solid #d2d2d2",
            padding: 8,
            background: "#f5f5f5",
          }}
        >
          <TextArea
            value={yamlContent}
            onChange={handleYamlChange}
            rows={10}
            style={{ fontFamily: "monospace", fontSize: 12 }}
            validated={isValid ? "default" : "error"}
          />
        </div>
      )}
    </div>
  );
}

export function FlowEditor(props: FlowEditorProps) {
  return (
    <ReactFlowProvider>
      <FlowEditorInner {...props} />
    </ReactFlowProvider>
  );
}
