import { PolicyTester } from "@/components/PolicyTester";

export default function PolicyPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-zinc-100">Policy Tester</h1>
        <p className="text-xs text-zinc-500">
          Dry-run any tool call against the live PolicyEngine — zero side effects, instant verdict.
        </p>
      </div>
      <PolicyTester />
    </div>
  );
}
