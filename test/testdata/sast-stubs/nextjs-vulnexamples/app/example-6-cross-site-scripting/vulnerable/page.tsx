import { notFound } from 'next/navigation';
import { getBlogPostById } from '../../../database/blogPosts';

export const dynamic = 'force-dynamic';

// VULNERABILITY: Uses dangerouslySetInnerHTML with unsanitized database content
// Blog post 6 contains: <img src="x" onerror="alert('pwned')" />
export default async function CrossSiteScriptingPage() {
  const blogPost = await getBlogPostById(6);

  if (!blogPost) {
    notFound();
  }

  return (
    <div>
      <h2>{blogPost.title}</h2>
      <div>Published: {String(blogPost.isPublished)}</div>

      <div
        dangerouslySetInnerHTML={{
          __html: blogPost.textContent,
        }}
      />
    </div>
  );
}
