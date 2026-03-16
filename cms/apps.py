from django.apps import AppConfig


class CmsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cms'

    def ready(self):
        from wagtail.models import Page
        from wagtail.admin.panels import FieldPanel, MultiFieldPanel
        from wagtail_ai.panels import AITitleFieldPanel, AIDescriptionFieldPanel

        # Apply AI panels globally to all Page models
        Page.content_panels = [AITitleFieldPanel("title")]
        Page.promote_panels = [
            MultiFieldPanel([
                FieldPanel("slug"),
                FieldPanel("seo_title"),
                AIDescriptionFieldPanel("search_description"),
            ], heading="For search engines"),
        ]
