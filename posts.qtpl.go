// Code generated by qtc from "posts.qtpl". DO NOT EDIT.
// See https://github.com/valyala/quicktemplate for details.

//line qtpl/posts.qtpl:1
package main

//line qtpl/posts.qtpl:2
import (
	qtio422016 "io"

	qt422016 "github.com/valyala/quicktemplate"
)

//line qtpl/posts.qtpl:2
var (
	_ = qtio422016.Copy
	_ = qt422016.AcquireByteBuffer
)

//line qtpl/posts.qtpl:2
func streamserveposts(qw422016 *qt422016.Writer, Posts []Post, CSRFToken string) {
//line qtpl/posts.qtpl:2
	qw422016.N().S(`
      <div class="isu-posts">
        `)
//line qtpl/posts.qtpl:4
	for _, post := range Posts {
//line qtpl/posts.qtpl:4
		qw422016.N().S(`
        <div class="isu-post" id="pid_`)
//line qtpl/posts.qtpl:5
		qw422016.N().D(post.ID)
//line qtpl/posts.qtpl:5
		qw422016.N().S(`" data-created-at="`)
//line qtpl/posts.qtpl:5
		qw422016.E().S(post.CreatedAt.Format("2006-01-02T15:04:05-07:00"))
//line qtpl/posts.qtpl:5
		qw422016.N().S(`">
          <div class="isu-post-header">
            <a href="/@`)
//line qtpl/posts.qtpl:7
		qw422016.E().S(post.User.AccountName)
//line qtpl/posts.qtpl:7
		qw422016.N().S(` " class="isu-post-account-name">`)
//line qtpl/posts.qtpl:7
		qw422016.E().S(post.User.AccountName)
//line qtpl/posts.qtpl:7
		qw422016.N().S(`</a>
            <a href="/posts/`)
//line qtpl/posts.qtpl:8
		qw422016.N().D(post.ID)
//line qtpl/posts.qtpl:8
		qw422016.N().S(`" class="isu-post-permalink">
              <time class="timeago" datetime="`)
//line qtpl/posts.qtpl:9
		qw422016.E().S(post.CreatedAt.Format("2006-01-02T15:04:05-07:00"))
//line qtpl/posts.qtpl:9
		qw422016.N().S(`"></time>
            </a>
          </div>
          <div class="isu-post-image">
            <img src="`)
//line qtpl/posts.qtpl:13
		qw422016.E().S(imageURL(post))
//line qtpl/posts.qtpl:13
		qw422016.N().S(`" class="isu-image">
          </div>
          <div class="isu-post-text">
            <a href="/@`)
//line qtpl/posts.qtpl:16
		qw422016.E().S(post.User.AccountName)
//line qtpl/posts.qtpl:16
		qw422016.N().S(`" class="isu-post-account-name">`)
//line qtpl/posts.qtpl:16
		qw422016.E().S(post.User.AccountName)
//line qtpl/posts.qtpl:16
		qw422016.N().S(`</a>
            `)
//line qtpl/posts.qtpl:17
		qw422016.E().S(post.Body)
//line qtpl/posts.qtpl:17
		qw422016.N().S(`
          </div>
          <div class="isu-post-comment">
            <div class="isu-post-comment-count">
              comments: <b>`)
//line qtpl/posts.qtpl:21
		qw422016.N().D(post.CommentCount)
//line qtpl/posts.qtpl:21
		qw422016.N().S(`</b>
            </div>

            `)
//line qtpl/posts.qtpl:24
		for _, comment := range post.Comments {
//line qtpl/posts.qtpl:24
			qw422016.N().S(`
            <div class="isu-comment">
              <a href="/@`)
//line qtpl/posts.qtpl:26
			qw422016.E().S(comment.User.AccountName)
//line qtpl/posts.qtpl:26
			qw422016.N().S(`" class="isu-comment-account-name">`)
//line qtpl/posts.qtpl:26
			qw422016.E().S(comment.User.AccountName)
//line qtpl/posts.qtpl:26
			qw422016.N().S(`</a>
              <span class="isu-comment-text">`)
//line qtpl/posts.qtpl:27
			qw422016.E().S(comment.Comment)
//line qtpl/posts.qtpl:27
			qw422016.N().S(`</span>
            </div>
            `)
//line qtpl/posts.qtpl:29
		}
//line qtpl/posts.qtpl:29
		qw422016.N().S(`
            <div class="isu-comment-form">
              <form method="post" action="/comment">
                <input type="text" name="comment">
                <input type="hidden" name="post_id" value="`)
//line qtpl/posts.qtpl:33
		qw422016.N().D(post.ID)
//line qtpl/posts.qtpl:33
		qw422016.N().S(`">
                <input type="hidden" name="csrf_token" value="`)
//line qtpl/posts.qtpl:34
		qw422016.E().S(CSRFToken)
//line qtpl/posts.qtpl:34
		qw422016.N().S(`">
                <input type="submit" name="submit" value="submit">
              </form>
            </div>
          </div>
        </div>

        `)
//line qtpl/posts.qtpl:41
	}
//line qtpl/posts.qtpl:41
	qw422016.N().S(`
`)
//line qtpl/posts.qtpl:42
}

//line qtpl/posts.qtpl:42
func writeserveposts(qq422016 qtio422016.Writer, Posts []Post, CSRFToken string) {
//line qtpl/posts.qtpl:42
	qw422016 := qt422016.AcquireWriter(qq422016)
//line qtpl/posts.qtpl:42
	streamserveposts(qw422016, Posts, CSRFToken)
//line qtpl/posts.qtpl:42
	qt422016.ReleaseWriter(qw422016)
//line qtpl/posts.qtpl:42
}

//line qtpl/posts.qtpl:42
func serveposts(Posts []Post, CSRFToken string) string {
//line qtpl/posts.qtpl:42
	qb422016 := qt422016.AcquireByteBuffer()
//line qtpl/posts.qtpl:42
	writeserveposts(qb422016, Posts, CSRFToken)
//line qtpl/posts.qtpl:42
	qs422016 := string(qb422016.B)
//line qtpl/posts.qtpl:42
	qt422016.ReleaseByteBuffer(qb422016)
//line qtpl/posts.qtpl:42
	return qs422016
//line qtpl/posts.qtpl:42
}
