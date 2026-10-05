import { PageHeader, Panel } from "@/components/ui";

export default function ContainersPage() {
  return (
    <>
      <PageHeader title="Containers" />
      <Panel>
        <p className="text-sm">
          Docker telemetry is not collected yet, so there is nothing to show here. The planned
          collector will report running containers, images, published ports, restart counts,
          privileged mode and host mounts, and this page will display them.
        </p>
        <p className="mt-3 text-sm text-[var(--muted)]">
          Until then, the rules for privileged containers and host mounts are not active either.
        </p>
      </Panel>
    </>
  );
}
