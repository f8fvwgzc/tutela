//! `tutela init`: a starter manifest.

/// A starter `tutela.resources.toml` for `app`. It compiles as it is: a
/// project with tasks, one custom action, one role and one UI key.
#[must_use]
pub fn starter(app: &str) -> String {
    format!(
        r#"# tutela.resources.toml: the permission model of this app.
# Format v1: docs/MANIFEST.md in the Tutela repository.
#   tutela check    compiles it and lists every problem
#   tutela apply    shows the diff, then applies it (a widening diff needs
#                   an approval token)
version = 1

[app]
name = "{app}"

[types.project]
parent    = "org"
container = true

[types.task]
parent = "project"

[types.task.fields]
title    = {{ sensitivity = "internal" }}
assignee = {{ sensitivity = "internal", type = "principal", grants_access = true }}

[types.task.actions]
close = {{ needs = "write" }}    # also needs the grant on the role

[roles.editor]
grants = {{ project = "read", task = "write", "task:close" = true }}

[ui."tasks.close_button"]
actions     = ["task:close"]
routes      = ["POST /api/tasks/{{id}}/close"]
when_denied = "disable"
reason      = "Only editors can close tasks."
"#
    )
}

#[cfg(test)]
mod tests {
    use tutela_pdp::model::Model;

    #[test]
    fn the_starter_compiles() {
        let m = Model::from_toml(&super::starter("crm")).unwrap();
        assert_eq!(m.app().as_str(), "crm");
        assert_eq!(m.types().len(), 2);
        assert_eq!(m.ui().len(), 1);
    }
}
