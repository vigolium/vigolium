import { WorkOS } from '@workos-inc/node';

let _workos: WorkOS | null = null;

export function getWorkOS(): WorkOS {
  if (!_workos) {
    _workos = new WorkOS(process.env.WORKOS_API_KEY);
  }
  return _workos;
}

export interface OrgInfo {
  orgId: string;
  orgName: string;
}

export interface OrgMember {
  id: string;
  membershipId: string;
  name: string;
  email: string;
  role: string;
  joinedAt: string;
}

/** Get the user's primary organization. */
export async function getUserOrganization(userId: string): Promise<OrgInfo | null> {
  const workos = getWorkOS();

  const memberships = await workos.userManagement.listOrganizationMemberships({
    userId,
  });

  if (memberships.data.length === 0) return null;

  const membership = memberships.data[0];
  const org = await workos.organizations.getOrganization(membership.organizationId);

  return {
    orgId: org.id,
    orgName: org.name,
  };
}

/** List members of an organization. */
export async function listOrgMembers(orgId: string): Promise<OrgMember[]> {
  const workos = getWorkOS();

  const memberships = await workos.userManagement.listOrganizationMemberships({
    organizationId: orgId,
  });

  const members: OrgMember[] = [];
  for (const m of memberships.data) {
    try {
      const user = await workos.userManagement.getUser(m.userId);
      members.push({
        id: user.id,
        membershipId: m.id,
        name: [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email,
        email: user.email,
        role: m.role?.slug || 'member',
        joinedAt: m.createdAt,
      });
    } catch {
      // skip users that can't be fetched
    }
  }

  return members;
}

/** Send an invitation to join the organization. */
export async function inviteMember(orgId: string, email: string): Promise<void> {
  const workos = getWorkOS();
  await workos.userManagement.sendInvitation({
    email,
    organizationId: orgId,
  });
}

/** Remove a member from the organization. */
export async function removeMember(membershipId: string): Promise<void> {
  const workos = getWorkOS();
  await workos.userManagement.deleteOrganizationMembership(membershipId);
}
