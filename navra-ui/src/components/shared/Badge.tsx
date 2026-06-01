interface BadgeProps {
  variant: 'onnx' | 'managed' | 'external' | 'success' | 'warning' | 'danger' | 'info' | 'accent';
  children: React.ReactNode;
}

export function Badge({ variant, children }: BadgeProps) {
  return <span className={`badge ${variant}`}>{children}</span>;
}
