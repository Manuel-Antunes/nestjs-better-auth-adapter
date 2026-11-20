/**
 * A project, as a resource. Named after its static `modelName`, as CASL
 * names classes: Better Auth's statement key is `project`.
 */
// biome-ignore lint/complexity/noStaticOnlyClass: a resource marker, as CASL takes them
export class Project {
	static readonly modelName = "project";
}
