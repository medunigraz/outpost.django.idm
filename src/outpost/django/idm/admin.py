import json

from django.contrib import admin
from django.utils.safestring import mark_safe
from polymorphic.admin import (
    PolymorphicChildModelAdmin,
    PolymorphicChildModelFilter,
    PolymorphicParentModelAdmin,
)
from pygments import (
    formatters,
    highlight,
    lexers,
)

from . import models


@admin.register(models.LDAPTarget)
class LDAPTargetAdmin(admin.ModelAdmin):
    list_display = (
        "url",
        "username",
        "group_base",
        "user_base",
        "enabled",
    )
    list_filter = ("enabled",)


class SourceExtractorInline(admin.TabularInline):
    model = models.SourceExtractor


class SourceResponderInline(admin.TabularInline):
    model = models.SourceResponder


class SourceChildAdmin(PolymorphicChildModelAdmin):
    """ Base admin class for all child models """

    base_model = models.Source
    inlines = (
        SourceExtractorInline,
        SourceResponderInline,
    )


@admin.register(models.KaduuSource)
class KaduuSourceAdmin(SourceChildAdmin):
    base_model = models.KaduuSource


@admin.register(models.Source)
class SourceParentAdmin(PolymorphicParentModelAdmin):
    """ The parent model admin """

    base_model = models.Source
    child_models = (models.KaduuSource,)
    list_filter = (PolymorphicChildModelFilter,)


class ExtractorChildAdmin(PolymorphicChildModelAdmin):
    """ Base admin class for all child models """

    base_model = models.Extractor


@admin.register(models.LanguageModelExtractor)
class LanguageModelExtractorAdmin(ExtractorChildAdmin):
    base_model = models.LanguageModelExtractor


@admin.register(models.RegularExpressionExtractor)
class RegularExpressionExtractorAdmin(ExtractorChildAdmin):
    base_model = models.RegularExpressionExtractor


@admin.register(models.Extractor)
class ExtractorParentAdmin(PolymorphicParentModelAdmin):
    """ The parent model admin """

    base_model = models.Extractor
    child_models = (
        models.LanguageModelExtractor,
        models.RegularExpressionExtractor,
    )
    list_filter = (PolymorphicChildModelFilter,)


class ResponderChildAdmin(PolymorphicChildModelAdmin):
    """ Base admin class for all child models """

    base_model = models.Responder


@admin.register(models.IncidentResponder)
class IncidentResponderAdmin(ResponderChildAdmin):
    base_model = models.IncidentResponder


@admin.register(models.JIRAResponder)
class JIRAResponderAdmin(ResponderChildAdmin):
    base_model = models.JIRAResponder


class MailResponderRecipientInline(admin.TabularInline):
    model = models.MailResponderRecipient


@admin.register(models.MailResponder)
class MailResponderAdmin(ResponderChildAdmin):
    base_model = models.MailResponder
    inlines = (MailResponderRecipientInline,)


@admin.register(models.SQLResponder)
class SQLResponderAdmin(ResponderChildAdmin):
    base_model = models.SQLResponder


@admin.register(models.Responder)
class ResponderParentAdmin(PolymorphicParentModelAdmin):
    """ The parent model admin """

    base_model = models.Responder
    child_models = (
        models.IncidentResponder,
        models.JIRAResponder,
        models.MailResponder,
        models.SQLResponder,
    )
    list_filter = (PolymorphicChildModelFilter,)


@admin.register(models.Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        "source",
        "user",
        "on",
    )
    list_filter = ("source",)
    date_hierarchy = "on"
    exclude = ("details",)
    readonly_fields = ("detail_view",)

    def detail_view(self, instance):
        return mark_safe(
            highlight(
                json.dumps(instance.details, sort_keys=True, indent=4),
                lexers.JsonLexer(),
                formatters.HtmlFormatter(),
            )
        )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
