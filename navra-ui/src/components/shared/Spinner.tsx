export function Spinner({ size = 'sm' }: { size?: 'sm' | 'lg' }) {
  return <span className={`spinner${size === 'lg' ? ' spinner-lg' : ''}`} />;
}
