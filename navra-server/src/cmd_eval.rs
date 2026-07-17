//! CLI dispatch for `navra eval` subcommands.

use crate::cli::EvalAction;
use crate::eval;

pub(crate) fn run(action: EvalAction) -> anyhow::Result<()> {
    match action {
        EvalAction::AgentDojo {
            tasks,
            suite,
            model,
            defense,
            attack,
            output,
            python,
        } => {
            eval::run_agentdojo(tasks, &suite, &model, &defense, &attack, output.as_deref(), &python)
        }
        EvalAction::McpTox { dataset, output } => {
            eval::run_mcptox(&dataset, output.as_deref())
        }
        EvalAction::Report { files, output } => {
            eval::run_report(&files, output.as_deref())
        }
    }
}
