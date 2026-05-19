import { getUnpublishedBlogPosts } from '../../../database/blogPosts';

export const dynamic = 'force-dynamic';

// VULNERABILITY: No authentication AND no authorization.
// Returns ALL users' unpublished blog posts to any visitor.
export default async function MissingAuthorizationServerComponentPage() {
  const blogPosts = await getUnpublishedBlogPosts();

  return (
    <div>
      <h1>Unpublished Blog Posts</h1>
      {blogPosts.map((post) => (
        <article key={`post-${post.id}`}>
          <h2>{post.title}</h2>
          <p>{post.textContent}</p>
        </article>
      ))}
    </div>
  );
}
