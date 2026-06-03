# Visualization Examples

Use the sanitized risk-test fixtures to generate local review artifacts without cloud credentials.

For committed example artifacts, see [the public admin path demo](../demo-public-admin-path). It includes self-contained HTML graph and attack-path visualizations plus a rendered SVG.

```bash
changegate graph export \
  --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --format dot \
  --out /tmp/changegate-graph.dot

changegate graph path \
  --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --from aws_lb.admin \
  --to aws_db_instance.customer \
  --format mermaid \
  --out /tmp/changegate-graph-path.mmd

changegate graph visualize \
  --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --view exposure \
  --resource aws_ecs_service.admin \
  --out /tmp/changegate-exposure.html

changegate attack-paths visualize \
  --plan examples/risk-tests/fixtures/passrole-lambda-update.json \
  --out /tmp/changegate-attack-paths.html
```

If Graphviz is installed, ChangeGate can render SVG, PNG, or PDF directly:

```bash
changegate graph render \
  --plan examples/risk-tests/fixtures/public-alb-ecs-rds.json \
  --view exposure \
  --resource aws_ecs_service.admin \
  --render-format svg \
  --out /tmp/changegate-exposure.svg
```

The HTML files are self-contained and do not fetch external JavaScript or CSS.
