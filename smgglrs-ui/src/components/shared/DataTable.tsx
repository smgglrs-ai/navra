import { useState, type ReactNode } from 'react';

export interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  mono?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyField: keyof T;
  expandable?: (row: T) => ReactNode;
  pagination?: {
    total: number;
    offset: number;
    limit: number;
    onPageChange: (offset: number) => void;
  };
}

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  keyField,
  expandable,
  pagination,
}: DataTableProps<T>) {
  const [expandedRow, setExpandedRow] = useState<unknown>(null);

  return (
    <div>
      <table className="data-table">
        <thead>
          <tr>
            {columns.map(col => (
              <th key={col.key}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map(row => {
            const key = row[keyField];
            const isExpanded = expandedRow === key;
            return (
              <tr key={String(key)}>
                {columns.map(col => (
                  <td
                    key={col.key}
                    className={col.mono ? 'mono' : ''}
                    onClick={expandable ? () => setExpandedRow(isExpanded ? null : key) : undefined}
                    style={expandable ? { cursor: 'pointer' } : undefined}
                  >
                    {col.render
                      ? col.render(row)
                      : String(row[col.key] ?? '')}
                  </td>
                ))}
              </tr>
            );
          })}
          {data.length === 0 && (
            <tr>
              <td colSpan={columns.length} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>
                No data
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {pagination && (
        <div className="table-pagination">
          <span>
            Showing {pagination.offset + 1}–{Math.min(pagination.offset + pagination.limit, pagination.total)} of {pagination.total}
          </span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn"
              disabled={pagination.offset === 0}
              onClick={() => pagination.onPageChange(Math.max(0, pagination.offset - pagination.limit))}
            >
              Previous
            </button>
            <button
              className="btn"
              disabled={pagination.offset + pagination.limit >= pagination.total}
              onClick={() => pagination.onPageChange(pagination.offset + pagination.limit)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
