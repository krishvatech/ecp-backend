"""Extra rich-text image formats (Wagtail loads ``image_formats`` modules of installed apps).

``logo``: a company logo inside a logo wall (the References page). Rendered at most 320x160
(never upscaled) with the class ``richtext-image logo``; the public frontend lays consecutive
logos out as a grid (src/components/public/StandardPageArticle.jsx). Editors pick it in the
image dialog as "Logo (logo wall)".
"""

from wagtail.images.formats import Format, register_image_format

LOGO_FORMAT = Format("logo", "Logo (logo wall)", "richtext-image logo", "max-320x160")

register_image_format(LOGO_FORMAT)
