CSS_SOURCES=./css_sources/main.scss
CSS=autonomie_oidc_provider/static/css/main.css


SASSC=$(shell which sassc)

all: css

css: warn cleancss $(CSS)

warn:
	@echo Note: using $(SASSC) for lessc

cleancss:
	@rm -f $(CSS)


$(CSS):	$(CSS_SOURCES)
	$(SASSC) $(CSS_SOURCES) $(CSS)

.PHONY: css, docs, warn, cleancss, compiled_js
