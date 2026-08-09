from inverba.models import FetchResult, FetchMethod
from inverba.extract import ExtractionPipeline

SAMPLE_HTML = b"""
<html>
<head><title>Test Page</title></head>
<body>
<article>
<h1>Hello World</h1>
<p>This is a test paragraph with enough content for trafilatura to extract
it confidently as the main body text of the page, rather than being
discarded as boilerplate.</p>
</article>
</body>
</html>
"""


def make_fetch_result(content: bytes) -> FetchResult:
    return FetchResult(
        url="https://example.com/article",
        final_url="https://example.com/article",
        status_code=200,
        content=content,
        content_type="text/html",
        method=FetchMethod.HTTP,
    )


def test_markdown_fast_path_extracts_content():
    pipeline = ExtractionPipeline()
    fr = make_fetch_result(SAMPLE_HTML)
    md = pipeline.to_markdown(fr)
    assert md is not None
    assert "Hello World" in md
    assert "test paragraph" in md


def test_extract_without_schema_skips_structured():
    pipeline = ExtractionPipeline()
    fr = make_fetch_result(SAMPLE_HTML)
    result = pipeline.extract(fr)
    assert result.markdown is not None
    assert result.structured is None
    assert result.model_used is None


def test_extract_with_schema_but_no_backend_raises():
    pipeline = ExtractionPipeline(model_backend=None)
    fr = make_fetch_result(SAMPLE_HTML)
    try:
        pipeline.extract(fr, schema={"type": "object"})
        assert False, "expected ValueError"
    except ValueError as e:
        assert "model_backend" in str(e)
