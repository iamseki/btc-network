import * as React from "react";

import { cn } from "@/lib/utils";

export interface TextInputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {}

export const TextInput = React.forwardRef<HTMLInputElement, TextInputProps>(
  ({ className, ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={cn(
          "flex h-12 w-full rounded-2xl border border-border bg-background px-4 py-3 text-sm text-foreground shadow-sm transition-colors outline-none placeholder:text-muted-foreground focus-visible:border-primary/60 focus-visible:ring-2 focus-visible:ring-primary/20",
          className,
        )}
        {...props}
      />
    );
  },
);
TextInput.displayName = "TextInput";
