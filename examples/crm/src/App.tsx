import { useQuery, useMutation } from "convex/react";
import { api as apiGeneric } from "../convex/_generated/api";
import { useState } from "react";

const api = apiGeneric;

// Simple types for verification
interface Access {
  canViewDeals: boolean;
  canCloseDeals: boolean;
  canManageBilling: boolean;
}


export default function App() {
  const [orgId, setOrgId] = useState("org_A");

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        <header className="flex justify-between items-center bg-white p-4 rounded shadow">
          <h1 className="text-2xl font-bold text-blue-900">CRM Example</h1>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-500">Current Org:</span>
            <select
              value={orgId}
              onChange={e => setOrgId(e.target.value)}
              className="border p-2 rounded bg-gray-50 font-medium"
            >
              <option value="org_A">Organization A</option>
              <option value="org_B">Organization B</option>
            </select>
          </div>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <ContactsSection orgId={orgId} />
          <div className="space-y-8">
            <AccessCheckSection orgId={orgId} />
            <RoleManagementSection orgId={orgId} />
          </div>
        </div>
      </div>
    </div>
  );
}

function ContactsSection({ orgId }: { orgId: string }) {
  const createContact = useMutation(api.contacts.create);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  return (
    <div className="bg-white p-6 rounded shadow">
      <h2 className="text-xl font-semibold mb-4 text-gray-800">Contacts</h2>
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <input
            placeholder="Name"
            value={name} onChange={e => setName(e.target.value)}
            className="border p-2 rounded w-full"
          />
          <input
            placeholder="Email"
            value={email} onChange={e => setEmail(e.target.value)}
            className="border p-2 rounded w-full"
          />
        </div>
        <button
          onClick={() => {
            createContact({ orgId, name, email })
              .then(() => { setName(""); setEmail(""); alert("Contact created!"); })
              .catch(e => alert(e.message));
          }}
          className="bg-green-600 text-white w-full py-2 rounded hover:bg-green-700 transition"
        >
          Create Contact
        </button>
        <p className="text-xs text-gray-400 mt-2">
          * Creating contacts requires `contacts:create` permission in this org.
        </p>
      </div>
    </div>
  );
}

function AccessCheckSection({ orgId }: { orgId: string }) {
  const access = useQuery(api.org.checkAccess, { orgId });

  if (!access) return <div className="bg-white p-6 rounded shadow">Loading permissions...</div>;

  return (
    <div className="bg-white p-6 rounded shadow">
      <h2 className="text-xl font-semibold mb-4 text-gray-800">Your Permissions</h2>
      <div className="grid grid-cols-3 gap-4">
        <PermissionBadge label="View Deals" allowed={access.canViewDeals} />
        <PermissionBadge label="Close Deals" allowed={access.canCloseDeals} />
        <PermissionBadge label="Manage Billing" allowed={access.canManageBilling} />
      </div>
    </div>
  );
}

function PermissionBadge({ label, allowed }: { label: string, allowed: boolean }) {
  return (
    <div className={`flex flex-col items-center justify-center p-3 rounded border ${allowed ? "bg-green-50 border-green-200" : "bg-red-50 border-red-200"}`}>
      <span className={`font-bold ${allowed ? "text-green-700" : "text-red-700"}`}>
        {allowed ? "✓ ALLOWED" : "✗ DENIED"}
      </span>
      <span className="text-xs text-gray-600 mt-1 text-center">{label}</span>
    </div>
  );
}

function RoleManagementSection({ orgId }: { orgId: string }) {
  const createRole = useMutation(api.org.createRole);
  const assignRole = useMutation(api.org.assignRole);

  const [roleName, setRoleName] = useState("");
  const [targetUser, setTargetUser] = useState("user_456");

  return (
    <div className="bg-white p-6 rounded shadow">
      <h2 className="text-xl font-semibold mb-4 text-gray-800">Admin: Dynamic Roles</h2>

      <div className="space-y-6">
        <div>
          <h3 className="text-sm font-semibold uppercase text-gray-500 mb-2">Create New Role</h3>
          <div className="flex gap-2">
            <input
              placeholder="Role Name (e.g. sales_manager)"
              value={roleName} onChange={e => setRoleName(e.target.value)}
              className="border p-2 rounded flex-1"
            />
            <button
              onClick={() => {
                createRole({
                  orgId,
                  roleName,
                  permissions: ["contacts:read", "deals:read"], // Hardcoded for demo
                  parentRole: "org:member"
                }).then(() => { setRoleName(""); alert("Role created!"); })
                  .catch(e => alert(e.message));
              }}
              className="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700"
            >
              Define Role
            </button>
          </div>
        </div>

        <div className="border-t pt-4">
          <h3 className="text-sm font-semibold uppercase text-gray-500 mb-2">Assign Role</h3>
          <div className="flex gap-2">
            <input
              placeholder="User ID"
              value={targetUser} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTargetUser(e.target.value)}
              className="border p-2 rounded w-1/3"
            />
            <input
              placeholder="Role to Assign"
              className="border p-2 rounded flex-1"
            />
            <button
              onClick={() => {
                // In real app, select role from list
                assignRole({ orgId, targetUserId: targetUser, roleName: "sales_manager" })
                  .then(() => alert("Role assigned!"))
                  .catch(e => alert(e.message));
              }}
              className="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-900"
            >
              Assign
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
