import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { useState } from "react";

import type { PeerAddress } from "@/lib/api/types";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;
const DEFAULT_PAGE_SIZE = 10;
const DEFAULT_SORT_COLUMN = "address";
const DEFAULT_SORT_DIRECTION = "asc";

type SortColumn = "network" | "address" | "port";
type SortDirection = "asc" | "desc";

export type PeerAddressTableProps = {
  addresses: PeerAddress[];
};

export function PeerAddressTable({ addresses }: PeerAddressTableProps) {
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [currentPage, setCurrentPage] = useState(1);
  const [sortColumn, setSortColumn] = useState<SortColumn>(DEFAULT_SORT_COLUMN);
  const [sortDirection, setSortDirection] = useState<SortDirection>(DEFAULT_SORT_DIRECTION);

  const sortedAddresses = [...addresses].sort((left, right) => {
    const comparison = comparePeerAddresses(left, right, sortColumn);
    return sortDirection === "asc" ? comparison : comparison * -1;
  });

  const totalPages = Math.max(1, Math.ceil(sortedAddresses.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const paginatedAddresses = sortedAddresses.slice(startIndex, startIndex + pageSize);
  const rangeStart = sortedAddresses.length === 0 ? 0 : startIndex + 1;
  const rangeEnd = sortedAddresses.length === 0 ? 0 : startIndex + paginatedAddresses.length;

  return (
    <Card className="border-border/80 bg-background/75">
      <CardHeader className="space-y-4 border-b border-border/70 bg-muted/20">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <CardTitle className="font-mono text-lg tracking-[0.18em] text-foreground">
                  Peer Address Directory
                </CardTitle>
                <Badge variant="muted">{addresses.length} discovered</Badge>
              </div>
              <CardDescription>
                A compact shadcn-style data panel with fixed pagination so large peer rosters stay
                readable.
              </CardDescription>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs uppercase tracking-[0.2em] text-muted-foreground">Rows</span>
              <div
                className="flex items-center rounded-[6px] border border-border bg-background/80 p-1"
                role="group"
                aria-label="Rows per page"
              >
                {PAGE_SIZE_OPTIONS.map((option) => (
                  <Button
                    key={option}
                    type="button"
                    size="sm"
                    variant={pageSize === option ? "secondary" : "ghost"}
                    className="min-w-11"
                    onClick={() => {
                      setPageSize(option);
                      setCurrentPage(1);
                    }}
                  >
                    {option}
                  </Button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-3 text-xs uppercase tracking-[0.2em] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
          <p>
            Showing {rangeStart}-{rangeEnd} of {sortedAddresses.length}
          </p>
          <div className="flex items-center gap-2">
            <span>Page {safeCurrentPage} of {totalPages}</span>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
              disabled={safeCurrentPage === 1}
            >
              Previous
            </Button>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
              disabled={safeCurrentPage === totalPages}
            >
              Next
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {addresses.length === 0 ? (
          <div className="px-6 py-10 text-sm text-muted-foreground">No peer addresses yet.</div>
        ) : (
          <>
            <div className="panel-scrollbar max-h-[26rem] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-muted/95 backdrop-blur-sm">
                  <tr>
                    <TableHead>
                      <SortHeader
                        column="network"
                        label="Network"
                        activeColumn={sortColumn}
                        direction={sortDirection}
                        onToggle={(column) => {
                          const nextDirection =
                            sortColumn === column && sortDirection === "asc" ? "desc" : "asc";
                          setSortColumn(column);
                          setSortDirection(nextDirection);
                          setCurrentPage(1);
                        }}
                      />
                    </TableHead>
                    <TableHead>
                      <SortHeader
                        column="address"
                        label="Address"
                        activeColumn={sortColumn}
                        direction={sortDirection}
                        onToggle={(column) => {
                          const nextDirection =
                            sortColumn === column && sortDirection === "asc" ? "desc" : "asc";
                          setSortColumn(column);
                          setSortDirection(nextDirection);
                          setCurrentPage(1);
                        }}
                      />
                    </TableHead>
                    <TableHead>
                      <SortHeader
                        column="port"
                        label="Port"
                        activeColumn={sortColumn}
                        direction={sortDirection}
                        onToggle={(column) => {
                          const nextDirection =
                            sortColumn === column && sortDirection === "asc" ? "desc" : "asc";
                          setSortColumn(column);
                          setSortDirection(nextDirection);
                          setCurrentPage(1);
                        }}
                      />
                    </TableHead>
                  </tr>
                </TableHeader>
                <TableBody>
                  {paginatedAddresses.map((entry) => (
                    <TableRow key={`${entry.network}-${entry.address}-${entry.port}`}>
                      <TableCell className="text-muted-foreground">{entry.network}</TableCell>
                      <TableCell className="break-all font-mono text-foreground">
                        {entry.address}
                      </TableCell>
                      <TableCell className="font-mono text-foreground">{entry.port}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

type SortHeaderProps = {
  column: SortColumn;
  label: string;
  activeColumn: SortColumn;
  direction: SortDirection;
  onToggle: (column: SortColumn) => void;
};

function SortHeader({ column, label, activeColumn, direction, onToggle }: SortHeaderProps) {
  const isActive = activeColumn === column;

  return (
    <button
      type="button"
      className="group inline-flex cursor-pointer items-center gap-2 text-left text-[11px] uppercase tracking-[0.22em] text-inherit transition-colors hover:text-foreground"
      onClick={() => onToggle(column)}
      aria-label={`Sort by ${label}`}
    >
      <span>{label}</span>
      {isActive ? (
        direction === "asc" ? (
          <ArrowUp className="h-3.5 w-3.5 transition-colors group-hover:text-foreground" />
        ) : (
          <ArrowDown className="h-3.5 w-3.5 transition-colors group-hover:text-foreground" />
        )
      ) : (
        <ArrowUpDown className="h-3.5 w-3.5 opacity-60 transition-all group-hover:opacity-100 group-hover:text-foreground" />
      )}
    </button>
  );
}

function comparePeerAddresses(
  left: PeerAddress,
  right: PeerAddress,
  column: SortColumn,
): number {
  if (column === "port") {
    return left.port - right.port;
  }

  return left[column].localeCompare(right[column]);
}
